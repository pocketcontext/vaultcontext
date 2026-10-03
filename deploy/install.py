#!/usr/bin/python3 -I
"""Install the fixed VaultContext deploy hook as root; takes no arguments or secrets."""
import os
from pathlib import Path
import subprocess
import sys
import tempfile

OLD = 'command="/usr/local/bin/deploy vault.pocketcontext.com"'
NEW = 'command="sudo -n /usr/local/sbin/deploy-vaultcontext"'


def rewrite_keys(text):
    lines = text.splitlines(keepends=True)
    matches = 0
    for i, line in enumerate(lines):
        if OLD in line or NEW in line:
            matches += 1
            lines[i] = line.replace(OLD, NEW)
    if not matches:
        raise RuntimeError("No exact VaultContext deployment key command found")
    return "".join(lines)


def atomic_write(path, data, mode, uid=0, gid=0):
    fd, name = tempfile.mkstemp(prefix=".vaultcontext-", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(data)
            os.fchmod(stream.fileno(), mode)
            os.fchown(stream.fileno(), uid, gid)
        os.replace(name, path)
    finally:
        if os.path.exists(name):
            os.unlink(name)


def main():
    if len(sys.argv) != 1 or os.geteuid() != 0:
        raise RuntimeError("Run this installer as root with no arguments")
    keys = Path("/home/deploy/.ssh/authorized_keys")
    if keys.is_symlink():
        raise RuntimeError("Refusing a symlink for authorized_keys")
    stat = keys.stat()
    rewritten = rewrite_keys(keys.read_text())
    source = Path(__file__).resolve().with_name("deploy-vaultcontext.py")
    sudoers = b'deploy ALL=(root) NOPASSWD: /usr/local/sbin/deploy-vaultcontext ""\n'
    with tempfile.NamedTemporaryFile() as candidate:
        candidate.write(sudoers)
        candidate.flush()
        subprocess.run(["/usr/sbin/visudo", "-cf", candidate.name], check=True)
    atomic_write(Path("/usr/local/sbin/deploy-vaultcontext"), source.read_bytes(), 0o755)
    atomic_write(Path("/etc/sudoers.d/deploy-vaultcontext"), sudoers, 0o440)
    atomic_write(keys, rewritten.encode(), stat.st_mode & 0o777, stat.st_uid, stat.st_gid)
    print("Installed VaultContext deployment hook; other authorized keys were preserved")


if __name__ == "__main__":
    main()
