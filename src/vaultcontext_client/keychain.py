"""Opt-in macOS credential retrieval through the separately signed native helper.

Only anonymous subprocess pipes carry credentials. Never surface helper output in
errors: both stdout and stderr must be treated as potentially secret-bearing.
"""
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import urllib.parse

from . import auth


def helper_path():
    return (Path.home() / 'Library/Application Support/VaultContext/KeychainHelper.app'
            / 'Contents/MacOS/vaultcontext-keychain')


def require_helper():
    if sys.platform != 'darwin':
        raise auth.Fail(2, 'Keychain unlock requires macOS. Use vc unlock for a terminal passphrase.')
    path = helper_path()
    # Do not resolve symlinks before checking: the installed helper and its
    # ancestors must not redirect execution to a different location.
    for candidate in (path, *path.parents):
        try:
            info = candidate.lstat()
        except OSError:
            raise auth.Fail(1, 'Install the signed VaultContext Keychain helper; see docs/macos-keychain.md.') from None
        if (stat.S_ISLNK(info.st_mode) or info.st_uid not in (0, os.getuid()) or
                info.st_mode & (stat.S_IWGRP | stat.S_IWOTH)):
            raise auth.Fail(1, 'Unsafe Keychain helper installation permissions.')
        if candidate == path:
            if not stat.S_ISREG(info.st_mode) or not os.access(path, os.X_OK):
                raise auth.Fail(1, 'Keychain helper is not executable.')
        elif not stat.S_ISDIR(info.st_mode):
            raise auth.Fail(1, 'Unsafe Keychain helper installation path.')
    return path


def origin(cfg):
    value = urllib.parse.urlsplit(cfg['url'])
    if (value.scheme not in ('http', 'https') or not value.hostname or
            value.username or value.password or value.path not in ('', '/') or
            value.query or value.fragment):
        raise auth.Fail(2, 'Keychain enrollment requires a server origin without a path, credentials, query or fragment.')
    host = value.hostname.lower()
    if ':' in host:
        host = '[' + host + ']'
    port = value.port
    suffix = '' if port is None or port == {'http': 80, 'https': 443}[value.scheme] else ':' + str(port)
    return value.scheme + '://' + host + suffix


def call(cfg, account, command, passphrase=None):
    path = require_helper()
    if command not in ('store', 'get', 'delete') or not isinstance(account, str) or not account:
        raise auth.Fail(2, 'Invalid Keychain request.')
    payload = {'origin': origin(cfg), 'account': account}
    if command == 'store':
        if not isinstance(passphrase, str) or not 1 <= len(passphrase.encode('utf-8')) <= 1024:
            raise auth.Fail(2, 'Invalid Keychain passphrase.')
        payload['passphrase'] = passphrase
    try:
        result = subprocess.run(
            [str(path), command], input=json.dumps(payload).encode('utf-8'),
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=120,
            env={'HOME': str(Path.home()), 'PATH': '/usr/bin:/bin'}, close_fds=True,
        )
    except subprocess.TimeoutExpired:
        raise auth.Fail(1, 'Keychain authentication timed out; no session opened.') from None
    except OSError:
        raise auth.Fail(1, 'Could not start the signed Keychain helper.') from None
    try:
        if len(result.stdout) > 8192:
            raise ValueError()
        response = json.loads(result.stdout)
        if not isinstance(response, dict):
            raise ValueError()
    except (ValueError, UnicodeError):
        raise auth.Fail(1, 'Invalid Keychain helper response; no credential used.') from None
    if result.returncode or response.get('ok') is not True:
        # Fixed messages only; do not echo arbitrary helper error strings.
        messages = {
            'not_found': 'No saved Keychain credential. Run vc keychain-enroll in your terminal.',
            'cancelled': 'Keychain authentication cancelled; no session opened.',
            'authentication_failed': 'Keychain authentication failed; use vc unlock in your terminal.',
            'interaction_not_allowed': 'Keychain authentication requires an interactive macOS login session.',
        }
        code = response.get('error')
        message = messages.get(code) if isinstance(code, str) else None
        raise auth.Fail(1, message or 'Keychain operation failed; check the signed helper installation or use vc unlock.')
    if command == 'get':
        secret = response.get('passphrase')
        if not isinstance(secret, str) or not 1 <= len(secret.encode('utf-8')) <= 1024:
            raise auth.Fail(1, 'Invalid Keychain credential; enroll again in your terminal.')
        return secret
    return None
