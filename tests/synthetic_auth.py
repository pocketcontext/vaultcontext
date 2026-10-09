"""Test-only token fixtures for isolated servers; never shipped with the client."""
from vaultcontext_client import auth


def cache_test_session(cfg, password):
    # Synthetic servers enable password auth only to mint test tokens. Mark the
    # fixture as Google so real CLI refresh/session handling is exercised; Google
    # exchange and callback behavior are covered separately in oauth.py.
    status, result = auth.send(cfg, 'POST', '/api/collections/users/auth-with-password',
                               {'identity': cfg['email'], 'password': password})
    if status != 200:
        raise AssertionError('Synthetic test authentication failed')
    return auth.auth_session(cfg, result, 'google')
