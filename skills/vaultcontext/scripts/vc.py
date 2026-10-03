#!/usr/bin/env python3
"""VaultContext file client. Private keys exist only in the unlocked process memory."""
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
import urllib.parse
import urllib.request

import vault_auth as auth
import vault_crypto as crypto

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
        revision = int(current['revision']) if current else 0
        epoch = int(vault['epoch'])
        key = vault_key(cfg, identity, account, vault['id'], epoch)
        data = crypto.read_file(args['path'])
        context = document_context(vault['id'], document, version, epoch)
        info = {'name': args.get('name') or Path(args['path']).name, 'size': len(data)}
        encrypted_info = metadata(key, info, dict(context, kind='file-metadata'))
        ciphertext = encode(crypto.encrypt_bytes(key, data, context))
        manifest = {'context': context, 'author': account, 'revision': revision + 1, 'metadata': encrypted_info, 'sha256': hashlib.sha256(ciphertext.encode()).hexdigest()}
        chunks = [ciphertext[i:i + 192 * 1024] for i in range(0, len(ciphertext), 192 * 1024)]
        return action(cfg, 'save', {'vault': vault['id'], 'document': document, 'version': version, 'expected_revision': revision, 'epoch': epoch, 'metadata': encrypted_info, 'manifest': encode(manifest), 'signature': crypto.sign_manifest(identity, manifest), 'chunks': chunks})
    if command in ('list', 'search'):
        result = []
        for doc in rows(cfg, 'documents', 'vault=' + quote(args['vault'])):
            _, info, ver = get_version(cfg, identity, account, doc['id'], content=False)
            if command != 'search' or args['text'].casefold() in info['name'].casefold():
                result.append(dict(id=doc['id'], revision=ver['revision'], **info))
        return result
    if command == 'history':
        result = []
        for ver in rows(cfg, 'versions', 'document=' + quote(args['document'])):
            _, info, checked = get_version(cfg, identity, account, args['document'], ver['id'], content=False)
            result.append(dict(version=checked['id'], revision=checked['revision'], author=checked['author'], **info))
        return sorted(result, key=lambda v: v['revision'])
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
                files.append({'document': doc['id'], 'version': ver['id'], 'revision': ver['revision'], 'name': info['name'], 'data': base64.b64encode(data).decode()})
        encrypted = crypto.encrypt_export(encode({'format': 'vaultcontext-export-v1', 'files': files}).encode(), args['export_passphrase'])
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
                except (BrokenPipeError, ConnectionResetError):
                    pass
                if stop:
                    break
    finally:
        server.close()
        path.unlink(missing_ok=True)
        os._exit(0)

def parser():
    p = argparse.ArgumentParser(description=__doc__)
    commands = p.add_subparsers(dest='command', required=True)
    def add(name, *positionals):
        q = commands.add_parser(name)
        for arg in positionals:
            q.add_argument(arg)
        return q
    q = add('login'); q.add_argument('--google', action='store_true'); q.add_argument('--port', type=int, default=8765); q.add_argument('--timeout', type=int, default=180)
    for name in ('whoami', 'logout', 'check', 'init', 'lock', 'vaults', 'invitations', 'change-passphrase'):
        add(name)
    q = add('unlock'); q.add_argument('--timeout', type=int, default=900)
    add('create', 'name')
    q = add('save', 'vault', 'path'); q.add_argument('--document'); q.add_argument('--name')
    add('list', 'vault'); add('search', 'vault', 'text'); add('history', 'document'); add('members', 'vault')
    q = add('restore', 'document'); q.add_argument('--version'); q.add_argument('--to', required=True); q.add_argument('--overwrite', action='store_true')
    q = add('share', 'vault', 'account'); q.add_argument('--role', choices=['reader', 'editor'], default='reader'); q.add_argument('--fingerprint', required=True)
    q = add('accept', 'invitation'); q.add_argument('--fingerprint', required=True)
    add('revoke', 'vault', 'account'); add('rotate', 'vault')
    q = add('verify-user', 'account'); q.add_argument('--fingerprint', required=True)
    add('directory')
    q = add('export', 'vault'); q.add_argument('--to', required=True); q.add_argument('--overwrite', action='store_true')
    add('inspect-export', 'archive')
    q = add('restore-export', 'archive'); q.add_argument('--document', required=True); q.add_argument('--version', required=True); q.add_argument('--to', required=True); q.add_argument('--overwrite', action='store_true')
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
    for key in ('path', 'to'):
        if payload.get(key):
            payload[key] = os.path.abspath(payload[key])
    if args.command == 'change-passphrase':
        payload['new_passphrase'] = prompt_passphrase(confirm=True)
    if args.command == 'export':
        payload['export_passphrase'] = prompt_passphrase(confirm=True)
    return session_call(cfg, payload)

def main():
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    try:
        result = run(parser().parse_args())
        print(encode(result))
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
