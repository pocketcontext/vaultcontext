#!/usr/bin/env python3
"""Build a provisioned helper bundle; never reads or writes a vault credential."""
import argparse
import datetime
import os
from pathlib import Path
import plistlib
import re
import shutil
import subprocess
import tempfile

BUNDLE_ID = "com.pocketcontext.vaultcontext.keychain"

def run(*args):
    # Never invoke a shell, and do not print signing/profile details.
    return subprocess.run(args, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).stdout

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--identity", required=True, help="Developer ID Application signing identity")
    parser.add_argument("--profile", type=Path, required=True, help="matching macOS provisioning profile")
    parser.add_argument("--team-id", required=True)
    parser.add_argument("--output", type=Path, required=True, help="new KeychainHelper.app path")
    args = parser.parse_args()
    if not re.fullmatch(r"[A-Z0-9]{10}", args.team_id) or args.identity == "-":
        parser.error("a real signing identity and ten-character team ID are required")
    output = args.output.expanduser().absolute()
    if output.suffix != ".app" or output.exists() or output.is_symlink():
        parser.error("output must be a new .app path")
    profile_bytes = args.profile.read_bytes()
    profile = plistlib.loads(run("/usr/bin/security", "cms", "-D", "-i", str(args.profile)))
    allowed = profile.get("Entitlements", {})
    app_id = args.team_id + "." + BUNDLE_ID
    expiry = profile.get("ExpirationDate")
    if not isinstance(expiry, datetime.datetime) or expiry <= datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None):
        parser.error("provisioning profile is expired or missing its expiration")
    allowed_id = allowed.get("com.apple.application-identifier", allowed.get("application-identifier"))
    groups = allowed.get("keychain-access-groups", [])
    if allowed_id != app_id or args.team_id not in profile.get("TeamIdentifier", []):
        parser.error("profile must authorize this exact bundle ID and team")
    if app_id not in groups and args.team_id + ".*" not in groups:
        parser.error("profile does not authorize the helper keychain access group")
    entitlements = {
        "com.apple.application-identifier": app_id,
        "com.apple.developer.team-identifier": args.team_id,
        "keychain-access-groups": [app_id],
    }
    output.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    with tempfile.TemporaryDirectory(prefix="vaultcontext-keychain-build-") as staging:
        root = Path(staging)
        bundle = root / "KeychainHelper.app"
        contents = bundle / "Contents"
        executable = contents / "MacOS" / "vaultcontext-keychain"
        executable.parent.mkdir(parents=True, mode=0o700)
        (contents / "Info.plist").write_bytes(plistlib.dumps({
            "CFBundleIdentifier": BUNDLE_ID,
            "CFBundleExecutable": executable.name,
            "CFBundleName": "VaultContext Keychain",
            "CFBundlePackageType": "APPL",
            "CFBundleVersion": "1",
            "CFBundleShortVersionString": "1.0",
            "LSMinimumSystemVersion": "12.0",
            "LSUIElement": True,
        }))
        (contents / "embedded.provisionprofile").write_bytes(profile_bytes)
        entitlement_path = root / "entitlements.plist"
        entitlement_path.write_bytes(plistlib.dumps(entitlements))
        # Build for this machine; distributed releases must build both architectures.
        arch = os.uname().machine
        if arch not in ("arm64", "x86_64"):
            parser.error("unsupported macOS architecture")
        run("/usr/bin/xcrun", "swiftc", "-O", "-warnings-as-errors", "-target", arch + "-apple-macosx12.0",
            "-o", str(executable), str(Path(__file__).with_name("main.swift")))
        run("/usr/bin/codesign", "--force", "--options", "runtime", "--timestamp",
            "--sign", args.identity, "--entitlements", str(entitlement_path), str(bundle))
        run("/usr/bin/codesign", "--verify", "--strict", str(bundle))
        # Published output has no group/other access, including the signed executable.
        for path in bundle.rglob("*"):
            path.chmod(0o700 if path.is_dir() or path == executable else 0o600)
        bundle.chmod(0o700)
        shutil.copytree(bundle, output)
    print("Signed helper bundle built. No Keychain item was accessed.")

if __name__ == "__main__":
    try:
        main()
    except subprocess.CalledProcessError:
        raise SystemExit("Build or signing command failed; verify the toolchain, identity and provisioning profile.")
