"""Private login defaults; tokens remain in their server/account session files."""
import json
import os
from pathlib import Path
import stat
import tempfile
import urllib.parse


def directory(app):
    override = os.environ.get(app.upper() + '_SESSION_DIR')
    return Path(override) if override else Path(os.environ.get('XDG_STATE_HOME') or Path.home() / '.local' / 'state') / app


def validate(url, email):
    if not isinstance(url, str) or not isinstance(email, str) or not url or not email:
        raise ValueError('Provide --url and --email for login, or set their application environment variables.')
    url = url.rstrip('/')
    parsed = urllib.parse.urlsplit(url)
    if (parsed.scheme not in ('http', 'https') or not parsed.hostname or parsed.username or parsed.password
            or parsed.query or parsed.fragment or any(c.isspace() or ord(c) < 32 for c in url)):
        raise ValueError('Server URL must be HTTP(S) without credentials, query, fragment or whitespace.')
    try:
        parsed.port
    except ValueError:
        raise ValueError('Server URL has an invalid port.') from None
    if parsed.scheme == 'http' and parsed.hostname not in ('localhost', '127.0.0.1', '::1'):
        raise ValueError('Use HTTPS for a remote server.')
    if '@' not in email or any(c.isspace() or ord(c) < 32 for c in email):
        raise ValueError('Provide a valid account email.')
    return {'url': url, 'email': email}


def _directory(path, create=False):
    # Reject symlink ancestors rather than redirecting private state elsewhere.
    for parent in (path, *path.parents):
        if parent.is_symlink():
            raise ValueError('Unsafe login state directory: symlinks are not allowed.')
    if create:
        path.mkdir(mode=0o700, parents=True, exist_ok=True)
    info = path.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700:
        raise ValueError('Login state directory must be owned by this user with mode 0700.')


def read(app):
    path = directory(app) / 'default.json'
    try:
        _directory(path.parent)
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except FileNotFoundError:
        return {}
    with os.fdopen(fd) as handle:
        info = os.fstat(handle.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o600 or info.st_size > 16384:
            raise ValueError('Login defaults must be a private regular file with mode 0600.')
        try:
            data = json.load(handle)
        except (ValueError, UnicodeError):
            raise ValueError('Invalid login defaults; sign in with explicit --url and --email to replace them.') from None
    if not isinstance(data, dict) or set(data) != {'url', 'email'}:
        raise ValueError('Invalid login defaults; expected URL and email only.')
    return validate(data['url'], data['email'])


def resolve(app, email_env, args=None):
    url = getattr(args, 'url', None) or os.environ.get(app.upper() + '_URL')
    email = getattr(args, 'email', None) or os.environ.get(email_env)
    saved = read(app) if not url or not email else {}
    return validate(url or saved.get('url'), email or saved.get('email'))


def save(app, cfg):
    data = validate(cfg['url'], cfg['email'])
    path = directory(app) / 'default.json'
    _directory(path.parent, create=True)
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(mode='w', dir=path.parent, prefix='.default-', delete=False) as handle:
            temporary = Path(handle.name)
            os.fchmod(handle.fileno(), 0o600)
            json.dump(data, handle)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def forget(app, cfg):
    if read(app) == {'url': cfg['url'], 'email': cfg['email']}:
        (directory(app) / 'default.json').unlink(missing_ok=True)
