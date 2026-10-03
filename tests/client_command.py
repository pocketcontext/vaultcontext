"""Exercise an installed package or an independently copied single-file launcher."""
from pathlib import Path
import shutil
import sys


def client_command(launcher, temporary):
    if launcher:
        destination = Path(temporary) / 'bin' / 'vc'
        destination.parent.mkdir()
        shutil.copy2(Path(launcher).resolve(), destination)
        assert destination.stat().st_mode & 0o111, 'launcher must be executable'
        return [str(destination)]
    return [sys.executable, '-m', 'vaultcontext_client.cli']
