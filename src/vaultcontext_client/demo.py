"""Public demo discovery and generation checks; no identity or key persistence."""
from datetime import datetime, timezone

from . import auth


def discover(cfg):
    status, data = auth.send(cfg, 'GET', '/api/demo/status')
    if status == 404:
        return None  # Older, non-demo servers do not expose this endpoint.
    if status != 200 or not isinstance(data, dict):
        raise auth.Fail(1, 'Server is unavailable or resetting; try again later.')
    if data.get('enabled') is False:
        return None
    if data.get('enabled') is not True:
        raise auth.Fail(1, 'Invalid demo status; refusing to continue.')
    try:
        generation = data['generation']
        day = datetime.strptime(generation, '%Y-%m-%d').date()
        reset = datetime.fromisoformat(data['resetAt'].replace('Z', '+00:00'))
        if (generation != day.isoformat() or reset.tzinfo is None or
                reset.utcoffset().total_seconds() != 0 or
                reset.hour != 0 or reset.minute != 0 or reset.second != 0 or
                (reset.date() - day).days != 1):
            raise ValueError('invalid deadline')
    except (KeyError, TypeError, ValueError, AttributeError):
        raise auth.Fail(1, 'Invalid demo generation; refusing to continue.') from None
    if datetime.now(timezone.utc) >= reset:
        raise auth.Fail(1, 'The demo is resetting. Wait for the new demo, then sign in and initialize a new identity.')
    return data


def configure(cfg, command):
    data = discover(cfg)
    if not data:
        return
    cfg['_demo_generation'] = data['generation']
    cfg['_demo_reset_at'] = data['resetAt']
    if command in ('keychain-enroll', 'share', 'accept', 'revoke', 'rotate', 'change-passphrase'):
        raise auth.Fail(2, 'This operation is unavailable in the disposable personal-vault demo.')


def guard(cfg):
    """Workers recheck their original generation before any key-bearing operation."""
    generation = cfg.get('_demo_generation')
    if generation is None:
        return
    data = discover(cfg)
    if not data or data['generation'] != generation:
        raise auth.Fail(1, 'The demo reset. Run vaultcontext lock, sign in again, then initialize and unlock a new identity. Existing fingerprint pins are not replaced automatically.')


def lifetime(cfg, seconds):
    if cfg.get('_demo_reset_at'):
        reset = datetime.fromisoformat(cfg['_demo_reset_at'].replace('Z', '+00:00'))
        seconds = min(seconds, int((reset - datetime.now(timezone.utc)).total_seconds()))
        if seconds < 30:
            raise auth.Fail(1, 'The daily reset is less than 30 seconds away. Wait before unlocking a new demo session.')
    return seconds
