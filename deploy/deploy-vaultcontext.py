#!/usr/bin/python3 -I
"""Root-owned, fixed-target ONCE update with a single SQLite/Litestream writer."""
import fcntl
import json
import os
import re
import subprocess
import sys

HOST = "vault.pocketcontext.com"
IMAGE = "ghcr.io/pocketcontext/vaultcontext:latest"
ENV = {"PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", "HOME": "/root"}


def run(*args, capture=False):
    result = subprocess.run(args, env=ENV, text=True, stdout=subprocess.PIPE if capture else None,
                            stderr=subprocess.PIPE if capture else None)
    if result.returncode:
        # Captured Docker metadata may contain credentials: never include its output.
        raise RuntimeError(f"{args[0]} {args[1]} failed (exit {result.returncode})")
    return result.stdout if capture else ""


def task_containers():
    ids = run("docker", "ps", "--all", "--filter", "label=once", "--format", "{{.ID}}", capture=True).split()
    containers = json.loads(run("docker", "inspect", *ids, capture=True)) if ids else []
    matches = [c for c in containers
               if json.loads(c.get("Config", {}).get("Labels", {}).get("once", "{}")).get("host") == HOST]
    return matches


def deploy():
    matches = task_containers()
    if len(matches) != 1:
        raise RuntimeError("Expected exactly one VaultContext container; refusing an ambiguous update")
    container = matches[0]
    if container["Config"]["Image"] != IMAGE and not re.fullmatch(
            r"ghcr\.io/pocketcontext/vaultcontext@sha256:[0-9a-f]{64}", container["Config"]["Image"]):
        raise RuntimeError("VaultContext image does not match the fixed deployment target")
    run("docker", "pull", IMAGE)
    try:
        run("docker", "stop", "--time", "60", container["Id"])
        state = json.loads(run("docker", "inspect", "--format", "{{json .State}}", container["Id"], capture=True))
        if state["Running"] or state["ExitCode"] != 0 or state.get("OOMKilled"):
            raise RuntimeError("VaultContext did not stop gracefully; refusing to replace it")
        run("once", "update", HOST, "--image", IMAGE, "--auto-update=false")
    except Exception:
        # ONCE retains the old stopped container when replacement fails to become healthy.
        # Recover service, but still fail the deployment so CI reports the failed update.
        try:
            remaining = task_containers()
            if len(remaining) != 1 or remaining[0]["Id"] != container["Id"]:
                raise RuntimeError("Recovery container is ambiguous; refusing to start another writer")
            run("docker", "start", container["Id"])
        except Exception:
            print("VaultContext recovery failed; operator intervention required", file=sys.stderr)
        raise


def main():
    if len(sys.argv) != 1:
        raise RuntimeError("This deployment command accepts no arguments")
    if os.geteuid() != 0:
        raise RuntimeError("This deployment command must run as root")
    with open("/run/lock/deploy-vaultcontext.lock", "a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        deploy()


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        # Exceptions never include captured metadata or configuration values.
        print(f"Deployment failed: {type(exc).__name__}: {exc}", file=sys.stderr)
        sys.exit(1)
