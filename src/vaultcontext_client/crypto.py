"""Version-one VaultContext cryptography and POSIX file IO. No key persistence.

All contexts must be reconstructed from the expected record identity, never trusted
from the encrypted payload. Authenticity is not server rollback detection. Python
cannot promise zeroization of immutable bytes or prevent privileged memory access.
"""
import base64
import hashlib
import json
import os
import secrets
import stat
from contextlib import contextmanager

from nacl import pwhash, utils
from nacl.exceptions import CryptoError
from nacl.public import PrivateKey, PublicKey, SealedBox
from nacl.secret import Aead
from nacl.signing import SigningKey, VerifyKey

MAX_FILE_SIZE = 8 * 1024 * 1024
MAX_PLAINTEXT = MAX_FILE_SIZE + 65536
KDF_OPS = 2
KDF_MEMORY = 64 * 1024 * 1024


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True, allow_nan=False).encode('ascii')


def b64(value):
    return base64.b64encode(value).decode('ascii')


def unb64(value, maximum=MAX_PLAINTEXT + 4096, exact=None):
    if not isinstance(value, str) or len(value) > ((maximum + 2) // 3) * 4:
        raise ValueError('invalid encoded data')
    try:
        raw = base64.b64decode(value, validate=True)
    except (ValueError, UnicodeError) as exc:
        raise ValueError('invalid encoded data') from exc
    if len(raw) > maximum or (exact is not None and len(raw) != exact) or b64(raw) != value:
        raise ValueError('invalid encoded data')
    return raw


def _fields(value, names):
    if not isinstance(value, dict) or set(value) != set(names):
        raise ValueError('unsupported format')


def _context(context):
    if not isinstance(context, dict) or not context:
        raise ValueError('nonempty context required')
    data = canonical({'domain': 'vaultcontext', 'v': 1, 'context': context})
    if len(data) > 4096:
        raise ValueError('context too large')
    return data


def generate_identity():
    return {'enc_private': b64(bytes(PrivateKey.generate())), 'sign_private': b64(bytes(SigningKey.generate()))}


def public_identity(identity):
    _fields(identity, ('enc_private', 'sign_private'))
    return {'enc_public': b64(bytes(PrivateKey(unb64(identity['enc_private'], exact=32)).public_key)),
            'sign_public': b64(bytes(SigningKey(unb64(identity['sign_private'], exact=32)).verify_key))}


def fingerprint(public):
    _fields(public, ('enc_public', 'sign_public'))
    unb64(public['enc_public'], exact=32)
    unb64(public['sign_public'], exact=32)
    return hashlib.sha256(b'vaultcontext-identity-v1\x00' + canonical(public)).hexdigest()


def new_vault_key():
    return utils.random(Aead.KEY_SIZE)


def encrypt_bytes(key, data, context):
    if not isinstance(data, bytes) or len(data) > MAX_PLAINTEXT:
        raise ValueError('plaintext exceeds limit or is not bytes')
    return {'v': 1, 'alg': 'xchacha20poly1305', 'ciphertext': b64(bytes(Aead(key).encrypt(data, _context(context))))}


def decrypt_bytes(key, envelope, context):
    _fields(envelope, ('v', 'alg', 'ciphertext'))
    if type(envelope['v']) is not int or envelope['v'] != 1 or envelope['alg'] != 'xchacha20poly1305':
        raise ValueError('unsupported encryption format')
    ciphertext = unb64(envelope['ciphertext'], MAX_PLAINTEXT + 40)
    return Aead(key).decrypt(ciphertext, _context(context))


def _password(passphrase):
    if not isinstance(passphrase, str) or not passphrase or len(passphrase.encode('utf-8')) > 1024:
        raise ValueError('passphrase must contain 1 to 1024 UTF-8 bytes')
    return passphrase.encode('utf-8')


def wrap_identity(identity, passphrase, user_id):
    public_identity(identity)
    if not isinstance(user_id, str) or not user_id:
        raise ValueError('user identity required')
    salt = utils.random(pwhash.argon2id.SALTBYTES)
    key = pwhash.argon2id.kdf(32, _password(passphrase), salt, opslimit=KDF_OPS, memlimit=KDF_MEMORY)
    return {'v': 1, 'kdf': 'argon2id', 'ops': KDF_OPS, 'memory': KDF_MEMORY, 'salt': b64(salt),
            'encrypted': encrypt_bytes(key, canonical(identity), {'purpose': 'private-identity', 'user': user_id})}


def unwrap_identity(bundle, passphrase, user_id):
    _fields(bundle, ('v', 'kdf', 'ops', 'memory', 'salt', 'encrypted'))
    if (type(bundle['v']) is not int or bundle['v'] != 1 or bundle['kdf'] != 'argon2id' or
        type(bundle['ops']) is not int or bundle['ops'] != KDF_OPS or
        type(bundle['memory']) is not int or bundle['memory'] != KDF_MEMORY):
        raise ValueError('unsupported KDF profile')
    if len(canonical(bundle)) > 4096:
        raise ValueError('identity bundle exceeds limit')
    salt = unb64(bundle['salt'], exact=pwhash.argon2id.SALTBYTES)
    key = pwhash.argon2id.kdf(32, _password(passphrase), salt, opslimit=KDF_OPS, memlimit=KDF_MEMORY)
    identity = json.loads(decrypt_bytes(key, bundle['encrypted'], {'purpose': 'private-identity', 'user': user_id}))
    public_identity(identity)
    return identity


def sign_manifest(identity, manifest):
    message = b'vaultcontext-manifest-v1\x00' + canonical(manifest)
    return b64(SigningKey(unb64(identity['sign_private'], exact=32)).sign(message).signature)


def verify_manifest(public, manifest, signature):
    VerifyKey(unb64(public['sign_public'], exact=32)).verify(
        b'vaultcontext-manifest-v1\x00' + canonical(manifest), unb64(signature, exact=64))


def seal_key(key, recipient_public, signer_identity, context):
    if not isinstance(key, bytes) or len(key) != 32:
        raise ValueError('invalid vault key')
    _context(context)
    body = {'v': 1, 'recipient': fingerprint(recipient_public), 'context': context,
            'ciphertext': b64(SealedBox(PublicKey(unb64(recipient_public['enc_public'], exact=32))).encrypt(key))}
    return {'body': body, 'signature': sign_manifest(signer_identity, body)}


def open_key(envelope, recipient_identity, signer_public, context):
    _context(context)
    _fields(envelope, ('body', 'signature'))
    body = envelope['body']
    _fields(body, ('v', 'recipient', 'context', 'ciphertext'))
    if len(canonical(envelope)) > 8192 or type(body['v']) is not int or body['v'] != 1:
        raise ValueError('unsupported key envelope')
    if canonical(body['context']) != canonical(context) or body['recipient'] != fingerprint(public_identity(recipient_identity)):
        raise ValueError('key envelope identity mismatch')
    verify_manifest(signer_public, body, envelope['signature'])
    key = SealedBox(PrivateKey(unb64(recipient_identity['enc_private'], exact=32))).decrypt(unb64(body['ciphertext'], exact=80))
    if len(key) != 32:
        raise ValueError('invalid vault key')
    return key


@contextmanager
def _parent(path):
    """Open every ancestor without following symlinks; anchor operations to dirfd."""
    path = os.fspath(path)
    if not isinstance(path, str) or not path or '\x00' in path:
        raise ValueError('invalid file path')
    absolute = os.path.isabs(path)
    parts = path.split('/')
    if parts[-1] in ('', '.', '..') or '..' in parts:
        raise ValueError('explicit non-traversing file path required')
    fd = os.open('/' if absolute else '.', os.O_RDONLY | os.O_DIRECTORY)
    try:
        for component in parts[:-1]:
            if component in ('', '.'):
                continue
            new_fd = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd)
            fd = new_fd
        yield fd, parts[-1]
    finally:
        os.close(fd)


def read_file(path, max_size=MAX_FILE_SIZE):
    return _read_regular(path, max_size, MAX_PLAINTEXT)


def read_archive(path):
    return _read_regular(path, MAX_EXPORT_SIZE * 4 // 3 + 8192, MAX_EXPORT_SIZE * 4 // 3 + 8192)


def _read_regular(path, max_size, upper_bound):
    if type(max_size) is not int or not 0 <= max_size <= upper_bound:
        raise ValueError('invalid size limit')
    with _parent(path) as (parent, name):
        fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
        with os.fdopen(fd, 'rb') as stream:
            before = os.fstat(stream.fileno())
            if not stat.S_ISREG(before.st_mode) or before.st_size > max_size:
                raise ValueError('input must be a regular file within the size limit')
            data = stream.read(max_size + 1)
            after = os.fstat(stream.fileno())
            fields = ('st_dev', 'st_ino', 'st_size', 'st_mtime_ns', 'st_ctime_ns')
            if len(data) > max_size or len(data) != before.st_size or any(getattr(before, f) != getattr(after, f) for f in fields):
                raise ValueError('input changed while being read')
            return data


def restore_file(path, data, overwrite=False):
    if not isinstance(data, bytes):
        raise ValueError('restore content must be bytes')
    with _parent(path) as (parent, name):
        try:
            existing = os.stat(name, dir_fd=parent, follow_symlinks=False)
        except FileNotFoundError:
            existing = None
        if existing is not None:
            if not stat.S_ISREG(existing.st_mode):
                raise ValueError('destination must be a regular file')
            if not overwrite:
                raise FileExistsError('destination already exists')
        temporary = '.vaultcontext-' + secrets.token_hex(16)
        fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=parent)
        try:
            with os.fdopen(fd, 'wb') as stream:
                os.fchmod(stream.fileno(), 0o600)
                stream.write(data)
                stream.flush()
                os.fsync(stream.fileno())
            if overwrite:
                os.replace(temporary, name, src_dir_fd=parent, dst_dir_fd=parent)
            else:
                os.link(temporary, name, src_dir_fd=parent, dst_dir_fd=parent, follow_symlinks=False)
                os.unlink(temporary, dir_fd=parent)
            os.fsync(parent)
        finally:
            try:
                os.unlink(temporary, dir_fd=parent)
            except FileNotFoundError:
                pass


MAX_EXPORT_SIZE = 64 * 1024 * 1024


def encrypt_export(data, passphrase):
    """Independent encrypted archive, no private-key bundle or recovery key."""
    if not isinstance(data, bytes) or len(data) > MAX_EXPORT_SIZE:
        raise ValueError('export exceeds size limit')
    salt = utils.random(pwhash.argon2id.SALTBYTES)
    key = pwhash.argon2id.kdf(32, _password(passphrase), salt, opslimit=KDF_OPS, memlimit=KDF_MEMORY)
    return {'v': 1, 'kind': 'vaultcontext-export', 'kdf': 'argon2id', 'ops': KDF_OPS,
            'memory': KDF_MEMORY, 'salt': b64(salt),
            'ciphertext': b64(bytes(Aead(key).encrypt(data, _context({'purpose': 'independent-export'}))))}


def decrypt_export(envelope, passphrase):
    _fields(envelope, ('v', 'kind', 'kdf', 'ops', 'memory', 'salt', 'ciphertext'))
    if (type(envelope['v']) is not int or envelope['v'] != 1 or envelope['kind'] != 'vaultcontext-export' or
        envelope['kdf'] != 'argon2id' or type(envelope['ops']) is not int or envelope['ops'] != KDF_OPS or
        type(envelope['memory']) is not int or envelope['memory'] != KDF_MEMORY):
        raise ValueError('unsupported export format')
    salt = unb64(envelope['salt'], exact=pwhash.argon2id.SALTBYTES)
    ciphertext = unb64(envelope['ciphertext'], MAX_EXPORT_SIZE + 40)
    key = pwhash.argon2id.kdf(32, _password(passphrase), salt, opslimit=KDF_OPS, memlimit=KDF_MEMORY)
    return Aead(key).decrypt(ciphertext, _context({'purpose': 'independent-export'}))


def parse_export(data):
    """Validate decrypted archive structure before displaying metadata or restoring."""
    import re
    if not isinstance(data, bytes) or len(data) > MAX_EXPORT_SIZE:
        raise ValueError('invalid archive size')
    archive = json.loads(data)
    _fields(archive, ('format', 'files'))
    if archive['format'] not in ('vaultcontext-export-v1', 'vaultcontext-export-v2') or not isinstance(archive['files'], list) or len(archive['files']) > 10000:
        raise ValueError('unsupported archive format')
    seen = set()
    for entry in archive['files']:
        fields = ('document', 'version', 'revision', 'name', 'data')
        if archive['format'] == 'vaultcontext-export-v2':
            fields += ('archived',)
        _fields(entry, fields)
        if archive['format'] == 'vaultcontext-export-v2' and type(entry['archived']) is not bool:
            raise ValueError('invalid archive document state')
        for field in ('document', 'version'):
            if not isinstance(entry[field], str) or not re.fullmatch(r'[a-z0-9]{15}', entry[field]):
                raise ValueError('invalid archive record identity')
        if type(entry['revision']) is not int or entry['revision'] < 1:
            raise ValueError('invalid archive revision')
        if not isinstance(entry['name'], str) or len(entry['name'].encode('utf-8')) > 65536:
            raise ValueError('invalid archive name')
        key = (entry['document'], entry['version'])
        if key in seen:
            raise ValueError('duplicate archive record')
        seen.add(key)
        unb64(entry['data'], maximum=MAX_FILE_SIZE)
    return archive
