#!/usr/bin/env python3
"""Store, version, restore and explicitly share encrypted files.

Private keys are stored encrypted on the server and decrypted only in memory.
"""
import argparse
import base64
import getpass
import hashlib
import json
import os
from pathlib import Path
import resource
import secrets
import socket
import stat
import struct
import sys
import time
import textwrap
import urllib.parse
import urllib.request

from . import auth
from . import crypto

MAX_FRAME = 24 * 1024 * 1024

def encode(value):
    return json.dumps(value, separators=(',', ':'), sort_keys=True)

def uid():
    return ''.join(secrets.choice('abcdefghijklmnopqrstuvwxyz0123456789') for _ in range(15))

def quote(value):
    return "'" + str(value).replace("'", "''") + "'"

def request(cfg, method, path, body=None):
    status, data = auth.call(cfg, method, path, body)
    if status >= 400:
        raise auth.Fail(4 if status == 409 else 1, f'HTTP {status}; operation failed. Reread state before retrying; response content suppressed.')
    return data

def query(cfg, sql):
    data = request(cfg, 'POST', '/api/context/query', {'sql': sql})
    if data.get('truncated'):
        raise auth.Fail(1, 'SQL response truncated; no partial result used.')
    return [row if isinstance(row, dict) else dict(zip(data['columns'], row)) for row in data['rows']]

def rows(cfg, table, where='1=1'):
    result = []
    offset = 0
    while True:
        page = query(cfg, f'SELECT * FROM {table} WHERE {where} ORDER BY id LIMIT 50 OFFSET {offset}')
        result.extend(page)
        if len(page) < 50:
            return result
        offset += len(page)

def one(cfg, table, where):
    values = rows(cfg, table, where)
    if len(values) != 1:
        raise auth.Fail(1, f'Expected one accessible {table} record.')
    return values[0]

def action(cfg, op, payload):
    return request(cfg, 'POST', '/api/collections/vault_actions/records', {'op': op, 'payload': payload})['result']

def whoami(cfg):
    return request(cfg, 'POST', '/api/collections/users/auth-refresh')['record']['id']

def public(row):
    return {'enc_public': row['public_key'], 'sign_public': row['signing_key']}

def pin_path(cfg):
    return auth.cache_file(cfg).with_suffix('.pins.json')

def pins(cfg):
    try:
        return json.loads(crypto.read_file(pin_path(cfg), max_size=65536))
    except FileNotFoundError:
        return {}

def verify_user(cfg, account, fingerprint=None):
    row = one(cfg, 'identities', 'account=' + quote(account))
    actual = crypto.fingerprint(public(row))
    if actual != row['fingerprint']:
        raise auth.Fail(1, 'Directory fingerprint mismatch.')
    known = pins(cfg)
    if fingerprint is not None:
        if not secrets.compare_digest(fingerprint, actual):
            raise auth.Fail(1, 'Fingerprint does not match the independently verified value.')
        known[account] = actual
        path = pin_path(cfg)
        path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        crypto.restore_file(path, encode(known).encode(), overwrite=True)
    elif known.get(account) != actual:
        raise auth.Fail(1, f'Unverified or changed public key for {account}; verify-user with an independently obtained fingerprint first.')
    return public(row)

def key_context(vault, account, epoch, signer):
    return {'kind': 'vault-key', 'vault': vault, 'recipient': account, 'epoch': epoch, 'signer': signer}

def seal(cfg, identity, key, vault, account, epoch, signer):
    recipient = verify_user(cfg, account)
    return encode({'signer': signer, 'sealed': crypto.seal_key(key, recipient, identity, key_context(vault, account, epoch, signer))})

def vault_key(cfg, identity, account, vault, epoch, expected_signer=None):
    row = one(cfg, 'key_envelopes', f'vault={quote(vault)} AND account={quote(account)} AND epoch={int(epoch)}')
    envelope = json.loads(row['envelope'])
    signer = envelope['signer']
    owner = expected_signer or one(cfg, 'vaults', 'id=' + quote(vault))['owner']
    if signer != owner:
        raise auth.Fail(1, 'Vault-key envelope was not signed by its owner.')
    return crypto.open_key(envelope['sealed'], identity, verify_user(cfg, signer), key_context(vault, account, epoch, signer))

def metadata(key, value, context):
    return encode(crypto.encrypt_bytes(key, encode(value).encode(), context))

def decrypt_metadata(key, value, context):
    return json.loads(crypto.decrypt_bytes(key, json.loads(value), context))

def download_chunk(cfg, chunk):
    token = request(cfg, 'POST', '/api/files/token')['token']
    path = '/api/files/version_chunks/' + urllib.parse.quote(chunk['id'], safe='') + '/' + urllib.parse.quote(chunk['ciphertext'], safe='')
    url = cfg['url'] + path + '?' + urllib.parse.urlencode({'token': token})
    try:
        with auth.opener.open(urllib.request.Request(url, headers={'User-Agent': auth.USER_AGENT}), timeout=30) as response:
            value = response.read(262145)
        if len(value) > 262144 or hashlib.sha256(value).hexdigest() != chunk['sha256']:
            raise ValueError('invalid chunk')
        return value.decode('utf-8')
    except Exception:
        raise auth.Fail(1, 'Protected chunk download failed; sensitive details suppressed.') from None

def document_context(vault, document, version, epoch):
    return {'kind': 'file', 'vault': vault, 'document': document, 'version': version, 'epoch': epoch}

def get_version(cfg, identity, account, document, version=None, content=True):
    doc = one(cfg, 'documents', 'id=' + quote(document))
    ver = one(cfg, 'versions', 'id=' + quote(version or doc['current_version']))
    if ver['document'] != document or ver['vault'] != doc['vault']:
        raise auth.Fail(1, 'Version/document mismatch.')
    if version is None and int(doc['revision']) != int(ver['revision']):
        raise auth.Fail(1, 'Current document revision mismatch.')
    key = vault_key(cfg, identity, account, doc['vault'], int(ver['epoch']))
    manifest = json.loads(ver['manifest'])
    crypto.verify_manifest(verify_user(cfg, ver['author']), manifest, ver['signature'])
    context = document_context(doc['vault'], document, ver['id'], int(ver['epoch']))
    if manifest['context'] != context or manifest['author'] != ver['author'] or manifest['revision'] != int(ver['revision']):
        raise auth.Fail(1, 'Signed manifest identity mismatch.')
    info = decrypt_metadata(key, manifest['metadata'], dict(context, kind='file-metadata'))
    if not content:
        return None, info, ver
    # Fetch individual chunks: a file must not overflow the SQL result byte budget.
    chunks = query(cfg, f'SELECT id,position FROM version_chunks WHERE version={quote(ver["id"])} ORDER BY position LIMIT 100')
    if len(chunks) != int(ver['chunk_count']) or [int(c['position']) for c in chunks] != list(range(len(chunks))):
        raise auth.Fail(1, 'Incomplete file chunks.')
    payload = ''.join(download_chunk(cfg, one(cfg, 'version_chunks', 'id=' + quote(c['id']))) for c in chunks)
    if hashlib.sha256(payload.encode()).hexdigest() != manifest['sha256']:
        raise auth.Fail(1, 'File integrity check failed.')
    data = crypto.decrypt_bytes(key, json.loads(payload), context)
    info = decrypt_metadata(key, manifest['metadata'], dict(context, kind='file-metadata'))
    if len(data) != info['size']:
        raise auth.Fail(1, 'File size mismatch.')
    return data, info, ver

def execute(cfg, identity, account, args):
    command = args['command']
    if command == 'change-passphrase':
        secret = one(cfg, 'identity_secrets', 'account=' + quote(account))
        bundle = crypto.wrap_identity(identity, args['new_passphrase'], account)
        return action(cfg, 'identity_rewrap', {'key_bundle': encode(bundle), 'expected_revision': secret['revision']})
    if command == 'create':
        vault, key = uid(), crypto.new_vault_key()
        return action(cfg, 'vault_create', {'id': vault, 'metadata': metadata(key, {'name': args['name']}, {'kind': 'vault-metadata', 'vault': vault}), 'envelope': seal(cfg, identity, key, vault, account, 1, account)})
    if command == 'vaults':
        result = []
        for vault in rows(cfg, 'vaults'):
            key = vault_key(cfg, identity, account, vault['id'], 1)
            result.append(dict(id=vault['id'], **decrypt_metadata(key, vault['metadata'], {'kind': 'vault-metadata', 'vault': vault['id']}), role=one(cfg, 'memberships', f'vault={quote(vault["id"])} AND account={quote(account)} AND active=1')['role']))
        return result
    if command == 'save':
        vault = one(cfg, 'vaults', 'id=' + quote(args['vault']))
        document, version = args.get('document') or uid(), uid()
        current = one(cfg, 'documents', 'id=' + quote(document)) if args.get('document') else None
        if current and current['vault'] != vault['id']:
            raise auth.Fail(1, 'Document belongs to another vault.')
        if current and current['archived']:
            raise auth.Fail(1, 'Document is archived; unarchive it before saving a new version.')
        revision = int(current['revision']) if current else 0
        archive_revision = int(current['archive_revision']) if current else 0
        epoch = int(vault['epoch'])
        key = vault_key(cfg, identity, account, vault['id'], epoch)
        data = crypto.read_file(args['path'])
        context = document_context(vault['id'], document, version, epoch)
        info = {'name': args['name'] if args.get('name') is not None else args['path'], 'size': len(data)}
        encrypted_info = metadata(key, info, dict(context, kind='file-metadata'))
        ciphertext = encode(crypto.encrypt_bytes(key, data, context))
        manifest = {'context': context, 'author': account, 'revision': revision + 1, 'metadata': encrypted_info, 'sha256': hashlib.sha256(ciphertext.encode()).hexdigest()}
        chunks = [ciphertext[i:i + 192 * 1024] for i in range(0, len(ciphertext), 192 * 1024)]
        return action(cfg, 'save', {'vault': vault['id'], 'document': document, 'version': version, 'expected_revision': revision, 'expected_archive_revision': archive_revision, 'epoch': epoch, 'metadata': encrypted_info, 'manifest': encode(manifest), 'signature': crypto.sign_manifest(identity, manifest), 'chunks': chunks})
    if command in ('archive', 'unarchive'):
        doc = one(cfg, 'documents', 'id=' + quote(args['document']))
        return action(cfg, command, {'vault': doc['vault'], 'document': doc['id'],
                                    'expected_revision': doc['revision'],
                                    'expected_archive_revision': doc['archive_revision']})
    if command in ('list', 'search'):
        result = []
        where = 'vault=' + quote(args['vault'])
        if not args.get('all'):
            where += ' AND archived=' + ('1' if args.get('archived') else '0')
        for doc in rows(cfg, 'documents', where):
            _, info, ver = get_version(cfg, identity, account, doc['id'], content=False)
            if command != 'search' or args['text'].casefold() in info['name'].casefold():
                result.append(dict(id=doc['id'], revision=ver['revision'], archived=bool(doc['archived']), **info))
        return result
    if command == 'history':
        result = []
        for ver in rows(cfg, 'versions', 'document=' + quote(args['document'])):
            _, info, checked = get_version(cfg, identity, account, args['document'], ver['id'], content=False)
            result.append(dict(version=checked['id'], revision=checked['revision'], author=checked['author'], **info))
        return sorted(result, key=lambda v: v['revision'])
    if command == 'cat':
        data, _, _ = get_version(cfg, identity, account, args['document'], args.get('version'))
        return {'data': base64.b64encode(data).decode('ascii')}
    if command == 'restore':
        data, _, ver = get_version(cfg, identity, account, args['document'], args.get('version'))
        crypto.restore_file(args['to'], data, overwrite=args.get('overwrite', False))
        return {'restored': ver['id'], 'bytes': len(data)}
    if command == 'members':
        return rows(cfg, 'memberships', 'vault=' + quote(args['vault']) + ' AND active=1')
    if command == 'share':
        verify_user(cfg, args['account'], args['fingerprint'])
        vault = one(cfg, 'vaults', 'id=' + quote(args['vault']))
        envelopes = [{'epoch': epoch, 'envelope': seal(cfg, identity, vault_key(cfg, identity, account, vault['id'], epoch), vault['id'], args['account'], epoch, account)} for epoch in range(1, int(vault['epoch']) + 1)]
        return action(cfg, 'share', {'vault': vault['id'], 'account': args['account'], 'role': args['role'], 'expected_revision': vault['revision'], 'envelopes': envelopes})
    if command == 'invitations':
        return rows(cfg, 'invitations', "status='pending'")
    if command == 'accept':
        invitation = one(cfg, 'invitations', 'id=' + quote(args['invitation']))
        verify_user(cfg, invitation['invited_by'], args['fingerprint'])
        offered = rows(cfg, 'key_envelopes', f'vault={quote(invitation["vault"])} AND account={quote(account)}')
        if not offered or sorted(int(e['epoch']) for e in offered) != list(range(1, len(offered) + 1)):
            raise auth.Fail(1, 'Incomplete invitation key history.')
        for envelope in offered:
            vault_key(cfg, identity, account, invitation['vault'], int(envelope['epoch']), expected_signer=invitation['invited_by'])
        return action(cfg, 'accept', {'invitation': invitation['id']})
    if command in ('revoke', 'rotate'):
        vault = one(cfg, 'vaults', 'id=' + quote(args['vault']))
        if command == 'revoke':
            action(cfg, 'revoke', {'vault': vault['id'], 'account': args['account'], 'expected_revision': vault['revision']})
            vault = one(cfg, 'vaults', 'id=' + quote(vault['id']))
        key, epoch = crypto.new_vault_key(), int(vault['epoch']) + 1
        members = rows(cfg, 'memberships', f'vault={quote(vault["id"])} AND active=1')
        envelopes = [{'account': m['account'], 'envelope': seal(cfg, identity, key, vault['id'], m['account'], epoch, account)} for m in members]
        return action(cfg, 'rotate', {'vault': vault['id'], 'expected_revision': vault['revision'], 'epoch': epoch, 'envelopes': envelopes})
    if command == 'export':
        files = []
        estimated_size = 128
        for doc in rows(cfg, 'documents', 'vault=' + quote(args['vault'])):
            for ver in rows(cfg, 'versions', 'document=' + quote(doc['id'])):
                data, info, _ = get_version(cfg, identity, account, doc['id'], ver['id'])
                estimated_size += ((len(data) + 2) // 3) * 4 + len(info['name'].encode('utf-8')) * 6 + 512
                if estimated_size > crypto.MAX_EXPORT_SIZE:
                    raise auth.Fail(1, 'Vault exceeds the 64 MiB plaintext archive limit.')
                files.append({'document': doc['id'], 'version': ver['id'], 'revision': ver['revision'], 'name': info['name'], 'archived': bool(doc['archived']), 'data': base64.b64encode(data).decode()})
        encrypted = crypto.encrypt_export(encode({'format': 'vaultcontext-export-v2', 'files': files}).encode(), args['export_passphrase'])
        crypto.restore_file(args['to'], encode(encrypted).encode(), overwrite=args.get('overwrite', False))
        return {'exported_versions': len(files)}
    raise auth.Fail(2, 'Unknown vault operation.')

# Local session: same-uid Unix socket, private directory, fixed lifetime, no key files.
def socket_path(cfg):
    return auth.cache_file(cfg).with_suffix('.sock')

def recv_frame(conn):
    data = bytearray()
    while b'\n' not in data:
        part = conn.recv(65536)
        if not part:
            raise ValueError('Incomplete session request')
        data.extend(part)
        if len(data) > MAX_FRAME:
            raise ValueError('Session request too large')
    return json.loads(bytes(data).split(b'\n', 1)[0])

def session_call(cfg, payload):
    path = socket_path(cfg)
    info = path.lstat()
    if not stat.S_ISSOCK(info.st_mode) or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o600:
        raise auth.Fail(1, 'Unsafe unlock session socket.')
    with socket.socket(socket.AF_UNIX) as conn:
        conn.settimeout(180)
        conn.connect(str(path))
        conn.sendall((encode(payload) + '\n').encode())
        result = recv_frame(conn)
    if 'error' in result:
        raise auth.Fail(result.get('code', 1), result['error'])
    return result['result']

def prompt_passphrase(confirm=False):
    if not sys.stdin.isatty():
        raise auth.Fail(2, 'Run this command in an interactive terminal; passphrases are never accepted through arguments, environment variables or stdin pipes.')
    value = getpass.getpass('Passphrase: ')
    if len(value) < 12:
        raise auth.Fail(2, 'Use a passphrase of at least 12 characters.')
    if confirm and value != getpass.getpass('Confirm passphrase: '):
        raise auth.Fail(2, 'Passphrases did not match.')
    return value

def unlock(cfg, timeout):
    if not 30 <= timeout <= 3600:
        raise auth.Fail(2, 'Unlock lifetime must be 30–3600 seconds.')
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    account = whoami(cfg)
    secret = one(cfg, 'identity_secrets', 'account=' + quote(account))
    identity = crypto.unwrap_identity(json.loads(secret['key_bundle']), prompt_passphrase(), account)
    verify_user(cfg, account, crypto.fingerprint(crypto.public_identity(identity)))
    path = socket_path(cfg)
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    if path.parent.is_symlink() or path.parent.stat().st_uid != os.getuid():
        raise auth.Fail(1, 'Unsafe session directory.')
    os.chmod(path.parent, 0o700)
    if path.exists():
        try:
            session_call(cfg, {'command': 'lock'})
            for _ in range(100):
                if not path.exists():
                    break
                time.sleep(.01)
        except (OSError, auth.Fail):
            raise auth.Fail(1, 'Existing session socket cannot be safely closed; inspect it before retrying.')
    server = socket.socket(socket.AF_UNIX)
    oldmask = os.umask(0o177)
    try:
        server.bind(str(path))
    finally:
        os.umask(oldmask)
    server.listen(4)
    server.settimeout(1)
    pid = os.fork()
    if pid:
        server.close()
        return {'unlocked': True, 'expires_in': timeout}
    os.setsid()
    null = os.open(os.devnull, os.O_RDWR)
    for fd in (0, 1, 2):
        os.dup2(null, fd)
    if null > 2:
        os.close(null)
    deadline = time.monotonic() + timeout
    try:
        while time.monotonic() < deadline:
            try:
                conn, _ = server.accept()
            except socket.timeout:
                continue
            with conn:
                if time.monotonic() >= deadline:
                    break
                conn.settimeout(5)
                peer = struct.unpack('3i', conn.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))[1]
                if peer != os.getuid():
                    continue
                stop = False
                try:
                    payload = recv_frame(conn)
                    stop = payload.get('command') == 'lock'
                    result = {'locked': True} if stop else execute(cfg, identity, account, payload)
                    response = {'result': result}
                except Exception as error:
                    response = {'error': str(error) if isinstance(error, auth.Fail) else 'Vault operation failed; sensitive error details suppressed.', 'code': getattr(error, 'code', 1)}
                try:
                    conn.sendall((encode(response) + '\n').encode())
                except OSError:
                    # A disconnected or stalled client must not end the unlock session.
                    pass
                if stop:
                    break
    finally:
        server.close()
        path.unlink(missing_ok=True)
        os._exit(0)

def parser():
    p = argparse.ArgumentParser(
        description=__doc__, usage='%(prog)s [-h] COMMAND ...',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""First use (replace the example URL and email):
  export VAULTCONTEXT_URL=https://vault.example.com
  export VAULTCONTEXT_USER_EMAIL=you@example.com
  vc login --google
  vc init                         # once per account; prompts for a passphrase
  vc unlock                       # prompts; session lasts 15 minutes
  vc create 'Personal'            # returns the VAULT_ID for save
  vc save VAULT_ID /path/to/file
  vc lock

Google login authenticates your account; unlock decrypts your keys.
Passphrases require an interactive terminal. There are no recovery keys.
Commands return JSON except cat, which writes exact file bytes to stdout.
Run vc COMMAND --help for arguments and examples.
Manual: https://github.com/pocketcontext/vaultcontext/blob/main/skills/vaultcontext/references/workflows.md""")
    commands = p.add_subparsers(prog=p.prog, dest='command', required=True, metavar='COMMAND',
                               help=argparse.SUPPRESS)
    summaries = {}
    positional_help = {
        'vault': ('VAULT_ID', 'vault ID from vc vaults or vc create'),
        'document': ('DOCUMENT_ID', 'document ID from vc list or vc search'),
        'account': ('ACCOUNT_ID', 'account ID from vc directory or vc members'),
        'invitation': ('INVITATION_ID', 'invitation ID from vc invitations'),
        'path': ('PATH', 'source file path; at most 8 MiB; symlinks rejected'),
        'name': ('NAME', 'display name for the new vault (encrypted on the server)'),
        'text': ('TEXT', 'case-insensitive fragment of the decrypted display name'),
        'archive': ('ARCHIVE', 'local encrypted archive created by vc export'),
    }

    def add(name, summary, description, example, *positionals):
        summaries[name] = summary
        q = commands.add_parser(
            name, description='\n\n'.join(textwrap.fill(part, width=76) for part in description.split('\n\n')),
            epilog='Example:\n  vc ' + example,
            formatter_class=argparse.RawDescriptionHelpFormatter)
        for arg in positionals:
            metavar, help_text = positional_help[arg]
            q.add_argument(arg, metavar=metavar, help=help_text)
        return q

    def archive_filters(q):
        group = q.add_mutually_exclusive_group()
        group.add_argument('--archived', action='store_true', help='include only archived documents')
        group.add_argument('--all', action='store_true', help='include active and archived documents')

    def destination(q):
        q.add_argument('--to', required=True, metavar='PATH',
                       help='destination file; parent directory must exist; symlinks rejected; mode 0600')
        q.add_argument('--overwrite', action='store_true',
                       help='replace an existing destination (default: refuse overwrite)')

    def fingerprint(q, person):
        q.add_argument('--fingerprint', required=True, metavar='FINGERPRINT',
                       help=f'{person} public-key fingerprint, verified through an independent trusted channel')

    unlocked = 'Requires login and an unlocked session (vc unlock). '
    q = add('login', 'Sign in to your account',
            'Sign in and cache an application token. Set VAULTCONTEXT_URL and '
            'VAULTCONTEXT_USER_EMAIL first. Use --google for browser sign-in, or '
            'VAULTCONTEXT_USER_PASSWORD for a provisioned password account. '
            'The account password is separate from the vault passphrase.\n\n'
            'Over SSH, forward the callback port: ssh -L 8765:127.0.0.1:8765 user@host. '
            'Open the printed URL on your browser machine; decryption stays on the CLI host.',
            'login --google')
    q.add_argument('--google', action='store_true', help='sign in with Google in a browser')
    q.add_argument('--port', type=int, default=8765,
                   help='Google callback port, 1–65535; with --google (default: %(default)s)')
    q.add_argument('--timeout', type=int, default=180,
                   help='Google sign-in wait in seconds, 1–600; with --google (default: %(default)s)')
    add('whoami', 'Show your authenticated account ID',
        'Refresh the application token and return your account ID. Requires login; no unlock needed.', 'whoami')
    add('logout', 'Lock and remove the local sign-in token',
        'Close the local unlock session and delete the cached application token for the configured '
        'server and email. Copied tokens are not revoked.', 'logout')
    add('check', 'Check server schema compatibility',
        'Compare the authenticated server SQL schema with this client\'s bundled snapshot. '
        'Requires login; no unlock needed. Exits with code 3 for schema differences.', 'check')
    add('init', 'Initialize your encryption identity once',
        'Requires login. Create your encryption/signing identity once per account. '
        'Prompts twice for a passphrase of at least 12 characters in an interactive terminal; '
        'stores the encrypted private-key bundle on the server and returns your public fingerprint. '
        'There are no recovery keys. Run vc unlock afterward.', 'init')
    q = add('unlock', 'Start a temporary session with keys in memory',
            'Requires login and an initialized identity (vc init). Prompts for your vault '
            'passphrase in an interactive terminal and starts a same-OS-user memory session. '
            'The execution host and agents using the session are trusted. Expiration rejects '
            'new requests; an operation already running may finish. Close early with vc lock.',
            'unlock --timeout 900')
    q.add_argument('--timeout', type=int, default=900,
                   help='session lifetime in seconds, 30–3600 (default: %(default)s)')
    add('lock', 'Close the local memory session',
        'End the unlocked session for the configured server and email. Keeps the application '
        'token; use vc logout to remove it too. Requires an existing unlock session.', 'lock')
    add('change-passphrase', 'Change your identity passphrase',
        unlocked + 'Prompt twice for a new passphrase (at least 12 characters) in an interactive '
        'terminal and re-encrypt the server identity bundle. This does not replace identity keys. '
        'An existing unlocked session can change a forgotten passphrase; there are no recovery keys.',
        'change-passphrase')
    add('vaults', 'List accessible vault names, IDs and roles',
        unlocked + 'Decrypt vault names and list your active vault memberships.', 'vaults')
    add('create', 'Create a private vault',
        unlocked + 'Create a vault you own and return its ID. Use vc share to invite members.',
        "create 'Personal'", 'name')
    q = add('save', 'Save a file or add an immutable version',
            unlocked + 'Owners and editors can save exact file bytes, up to 8 MiB. By default '
            'creates a new document; --document adds an immutable version to an existing document '
            'in the same vault. Archived documents must be unarchived first. Names are encrypted; '
            'the default preserves the exact source path argument as a label, without normalization. '
            'Names are not unique and never select restore destinations. Symlink sources and ancestors are rejected.',
            'save VAULT_ID /path/to/file --document DOCUMENT_ID', 'vault', 'path')
    q.add_argument('--document', metavar='DOCUMENT_ID',
                   help='existing document ID from vc list; omit to create a new document')
    q.add_argument('--name', metavar='NAME',
                   help='encrypted display name for this version (default: exact source path argument)')
    q = add('list', 'List files and document IDs in a vault',
        unlocked + 'Authenticate current versions and show decrypted names, sizes, revisions and '
        'archive status. Lists active documents by default. Does not print file contents. '
        'Verify other writers with vc verify-user first.', 'list VAULT_ID --all', 'vault')
    archive_filters(q)
    q = add('search', 'Search decrypted file names',
        unlocked + 'Search current display names locally, ignoring case. Searches active documents '
        'by default. Does not search file contents. Verify other writers with vc verify-user first.',
        'search VAULT_ID project --archived', 'vault', 'text')
    archive_filters(q)
    add('archive', 'Hide a document from active file listings',
        unlocked + 'Owners and editors can archive an entire document and all its versions. '
        'Repeated requests are harmless. Blocks new versions until unarchived; history, cat and '
        'restore remain available by ID. Does not delete data, reclaim storage or revoke access. '
        'Exports and whole-vault sharing still include archived documents.',
        'archive DOCUMENT_ID', 'document')
    add('unarchive', 'Return an archived document to active listings',
        unlocked + 'Owners and editors can unarchive a document, allowing new versions again. '
        'Repeated requests are harmless. Preserves all retained versions.',
        'unarchive DOCUMENT_ID', 'document')
    add('history', 'List a document\'s retained versions',
        unlocked + 'Authenticate retained versions and show version IDs, revisions, authors, '
        'names and sizes. Verify other writers with vc verify-user first.', 'history DOCUMENT_ID', 'document')
    q = add('cat', 'Write exact file contents to stdout',
            unlocked + 'Write exact bytes, defaulting to the current version, after verifying '
            'the entire file. Verify the writer with vc verify-user first. No JSON, headings or '
            'added newline; errors go to stderr. Creates no plaintext temporary files and never '
            'executes contents. Output may contain secrets, binary data or terminal control '
            'characters. Shell redirection uses ordinary shell permissions and overwrite behavior; '
            'use vc restore for protected file creation.',
            'cat DOCUMENT_ID --version VERSION_ID', 'document')
    q.add_argument('--version', metavar='VERSION_ID',
                   help='version ID from vc history (default: current version)')
    q = add('restore', 'Restore a file version to a local path',
            unlocked + 'Restore exact bytes, defaulting to the current version. Verify the '
            'writer with vc verify-user first. Existing destinations require --overwrite. '
            'Parents must exist; symlink destinations and ancestors are rejected. Writes mode '
            '0600; original permissions and executable bits are not restored. Never executes the file.',
            'restore DOCUMENT_ID --to /path/to/destination', 'document')
    q.add_argument('--version', metavar='VERSION_ID',
                   help='version ID from vc history (default: current version)')
    destination(q)
    add('directory', 'List registered accounts and public keys',
        'Requires login; no unlock needed. List user names, emails, account IDs and public keys. '
        'Directory values are not independent proof of identity; verify fingerprints through a trusted channel.',
        'directory')
    q = add('verify-user', 'Pin an independently verified fingerprint',
            'Requires login; no unlock needed. Compare the supplied fingerprint with the account\'s '
            'public keys and pin it locally for this server and user. Verify owners and writers '
            'before reading their signed data; verify recipients before sharing.',
            'verify-user ACCOUNT_ID --fingerprint VERIFIED_FINGERPRINT', 'account')
    fingerprint(q, 'account')
    add('members', 'List active vault members and roles',
        unlocked + 'List active owner, editor and reader memberships with account IDs.', 'members VAULT_ID', 'vault')
    q = add('share', 'Invite a reader or editor to the whole vault',
            unlocked + 'Owner only. Verify the recipient fingerprint independently. Acceptance '
            'grants the whole vault and all retained history. Use a dedicated vault for a single-file '
            'share. To change an active member\'s role, revoke/rotate and then invite again.',
            'share VAULT_ID ACCOUNT_ID --role reader --fingerprint VERIFIED_RECIPIENT_FINGERPRINT',
            'vault', 'account')
    q.add_argument('--role', choices=['reader', 'editor'], default='reader',
                   help='reader can restore; editor can also save (default: %(default)s)')
    fingerprint(q, 'recipient')
    add('invitations', 'List accessible pending invitations',
        unlocked + 'List pending invitations and their IDs. Use vc accept for an invitation addressed to you.',
        'invitations')
    q = add('accept', 'Accept a vault invitation',
            unlocked + 'Verify the owner\'s fingerprint independently, authenticate the offered '
            'key history, then accept your invitation.',
            'accept INVITATION_ID --fingerprint VERIFIED_OWNER_FINGERPRINT', 'invitation')
    fingerprint(q, 'owner')
    add('revoke', 'Remove a member and rotate future-write keys',
        unlocked + 'Owner only; owners cannot remove themselves. Revoke the member, cancel pending '
        'invitations and freeze writes before rotating keys for remaining members. Previously '
        'downloaded plaintext and keys cannot be recalled; rotation protects future versions. '
        'If rotation fails, verify remaining members and run vc rotate. Reissue canceled invitations afterward.',
        'revoke VAULT_ID ACCOUNT_ID', 'vault', 'account')
    add('rotate', 'Rotate vault keys or finish a failed revocation',
        unlocked + 'Owner only. Independently verify and pin all remaining member fingerprints '
        'with vc verify-user first. Publish keys for a new generation and unfreeze writes after '
        'revocation. Existing versions keep their original keys; reissue canceled invitations afterward.',
        'rotate VAULT_ID', 'vault')
    q = add('export', 'Export retained files to an encrypted archive',
            unlocked + 'Export all accessible retained file versions. Prompts twice for a separate '
            'archive passphrase in an interactive terminal. Includes archived documents and their status. '
            'Contains no identity private keys or '
            'live vault-key envelopes and cannot recover your live-vault passphrase. The plaintext '
            'archive limit is 64 MiB, including base64 and metadata. Restore without a server using '
            'vc restore-export. Parent directory must exist; output mode is 0600.',
            'export VAULT_ID --to /path/to/files.vault-export', 'vault')
    destination(q)
    add('inspect-export', 'List document and version IDs in an archive',
        'Works offline without server configuration, login or unlock. Prompts for the archive '
        'passphrase in an interactive terminal and decrypts in memory. Lists metadata without '
        'file contents; use its document/version IDs with vc restore-export.',
        'inspect-export /path/to/files.vault-export', 'archive')
    q = add('restore-export', 'Restore one file from an encrypted archive',
            'Works offline without server configuration, login or unlock. Prompts for the archive '
            'passphrase in an interactive terminal. Decrypts in memory and writes only the selected '
            'file, with mode 0600. Parent directory must exist; symlink destinations and ancestors '
            'are rejected. Refuses existing destinations unless --overwrite is supplied. Never executes the file.',
            'restore-export /path/to/files.vault-export --document DOCUMENT_ID --version VERSION_ID --to /path/to/file',
            'archive')
    q.add_argument('--document', required=True, metavar='DOCUMENT_ID', help='document ID from vc inspect-export')
    q.add_argument('--version', required=True, metavar='VERSION_ID', help='version ID from vc inspect-export')
    destination(q)

    groups = [
        ('Account and keys', ('login', 'whoami', 'logout', 'check', 'init', 'unlock', 'lock', 'change-passphrase')),
        ('Vaults and files', ('vaults', 'create', 'save', 'list', 'search', 'history', 'cat', 'restore', 'archive', 'unarchive')),
        ('Sharing', ('directory', 'verify-user', 'members', 'share', 'invitations', 'accept', 'revoke', 'rotate')),
        ('Encrypted archives', ('export', 'inspect-export', 'restore-export')),
    ]
    p.epilog = '\n\n'.join(
        title + ':\n' + '\n'.join(f'  {name:19} {summaries[name]}' for name in names)
        for title, names in groups) + '\n\n' + p.epilog
    return p

def run(args):
    if args.command in ('restore-export', 'inspect-export'):
        archive = json.loads(crypto.read_archive(args.archive))
        data = crypto.parse_export(crypto.decrypt_export(archive, prompt_passphrase()))
        if args.command == 'inspect-export':
            return [{k: v for k, v in f.items() if k != 'data'} for f in data['files']]
        matches = [f for f in data['files'] if f['document'] == args.document and f['version'] == args.version]
        if len(matches) != 1:
            raise auth.Fail(1, 'Export does not contain that document/version.')
        crypto.restore_file(args.to, base64.b64decode(matches[0]['data'], validate=True), overwrite=args.overwrite)
        return {'restored': args.version}
    cfg = auth.config()
    if args.command == 'login':
        (auth.google_login(cfg, args.port, args.timeout) if args.google else auth.login(cfg))
        return {'signed_in': True}
    if args.command == 'logout':
        try:
            session_call(cfg, {'command': 'lock'})
        except FileNotFoundError:
            pass
        auth.cache_file(cfg).unlink(missing_ok=True)
        return {'signed_out': True}
    if args.command == 'whoami':
        return {'id': whoami(cfg)}
    if args.command == 'check':
        schema = request(cfg, 'GET', '/api/context/schema')
        expected = json.loads(auth.SCHEMA_FILE.read_text())
        actual = {t['name']: sorted(c['name'] for c in t['columns']) for t in schema['tables']}
        if actual != expected:
            raise auth.Fail(3, 'Server schema differs from the bundled schema snapshot.')
        return {'compatible': True}
    if args.command == 'directory':
        return {'users': rows(cfg, 'user_directory'), 'keys': rows(cfg, 'identities')}
    if args.command == 'verify-user':
        verify_user(cfg, args.account, args.fingerprint)
        return {'verified': args.account}
    if args.command == 'init':
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
        account = whoami(cfg)
        identity = crypto.generate_identity()
        bundle = crypto.wrap_identity(identity, prompt_passphrase(confirm=True), account)
        pub = crypto.public_identity(identity)
        fingerprint = crypto.fingerprint(pub)
        result = action(cfg, 'identity_init', {'public_key': pub['enc_public'], 'signing_key': pub['sign_public'], 'fingerprint': fingerprint, 'key_bundle': encode(bundle)})
        verify_user(cfg, account, fingerprint)
        return dict(result, fingerprint=fingerprint)
    if args.command == 'unlock':
        return unlock(cfg, args.timeout)
    payload = vars(args).copy()
    if args.command == 'save' and payload.get('name') is None:
        payload['name'] = payload['path']
    for key in ('path', 'to'):
        if payload.get(key):
            payload[key] = os.path.abspath(payload[key])
    if args.command == 'change-passphrase':
        payload['new_passphrase'] = prompt_passphrase(confirm=True)
    if args.command == 'export':
        payload['export_passphrase'] = prompt_passphrase(confirm=True)
    result = session_call(cfg, payload)
    if args.command == 'cat':
        return base64.b64decode(result['data'], validate=True)
    return result

def main():
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    try:
        command_parser = parser()
        if len(sys.argv) == 1:
            command_parser.print_help()
            return 0
        args = command_parser.parse_args()
        result = run(args)
        if args.command == 'cat':
            sys.stdout.buffer.write(result)
            sys.stdout.buffer.flush()
        else:
            print(encode(result))
    except BrokenPipeError:
        # Prevent another flush of a closed pipe during interpreter shutdown.
        with open(os.devnull, 'wb') as sink:
            os.dup2(sink.fileno(), sys.stdout.fileno())
        return 1
    except auth.Fail as error:
        auth.say(str(error)); return error.code
    except FileNotFoundError:
        auth.say('Required file or unlock session missing; check paths or run unlock.'); return 1
    except KeyboardInterrupt:
        auth.say('Cancelled.'); return 1
    except Exception:
        auth.say('Vault operation failed; sensitive error details suppressed.'); return 1
    return 0

if __name__ == '__main__':
    raise SystemExit(main())
