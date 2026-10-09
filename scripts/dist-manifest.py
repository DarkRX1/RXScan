#!/usr/bin/env python3
"""Generate dist/release-manifest.json for RXScan distribution archives.

Scans dist/ for RXScan-*.(tar.gz|zip|apk), records per-artifact metadata:
filename, platform, arch, target triple, artifact type, version, git commit,
sha256, byte size. Privacy: only repository-derived facts; no usernames,
hostnames, absolute local paths, or environment details.

Usage: python3 scripts/dist-manifest.py [--dist DIR] [--out FILE]
Environment: RXSCAN_VERSION (else derived from Cargo.toml),
RXSCAN_COMMIT (else `git rev-parse HEAD`).
"""
import hashlib
import json
import os
import re
import subprocess
import sys

NAME_RE = re.compile(
    r"^RXScan-(?P<version>[^-]+?)(?P<dev>-dev)?-"
    r"(?P<os>windows|linux|macos|android)-(?P<arch>[A-Za-z0-9_]+)"
    r"(?P<musl>-musl)?\.(?P<ext>tar\.gz|zip|apk)$"
)

TARGET_FOR = {
    ("linux", "x86_64", ""): "x86_64-unknown-linux-gnu",
    ("linux", "aarch64", ""): "aarch64-unknown-linux-gnu",
    ("linux", "x86_64", "-musl"): "x86_64-unknown-linux-musl",
    ("linux", "aarch64", "-musl"): "aarch64-unknown-linux-musl",
    ("windows", "x86_64", ""): "x86_64-pc-windows-msvc",
    ("macos", "arm64", ""): "aarch64-apple-darwin",
    ("macos", "x86_64", ""): "x86_64-apple-darwin",
    ("android", "arm64", ""): "aarch64-linux-android",
}

ARTIFACT_TYPE = {".apk": "apk", ".zip": "zip", ".tar.gz": "tarball"}


def repo_version():
    explicit = os.environ.get("RXSCAN_VERSION")
    if explicit:
        return explicit.strip()
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    text = open(os.path.join(root, "Cargo.toml"), encoding="utf-8").read()
    match = re.search(r'^version\s*=\s*"([^"]+)"', text, re.MULTILINE)
    if not match:
        raise SystemExit("cannot determine package version from Cargo.toml")
    return match.group(1)


def repo_commit():
    explicit = os.environ.get("RXSCAN_COMMIT")
    if explicit:
        return explicit.strip()
    out = subprocess.run(
        ["git", "rev-parse", "HEAD"], capture_output=True, text=True, check=True
    )
    return out.stdout.strip()


def sha256_of(path):
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def ext_of(filename):
    for ext in (".tar.gz", ".zip", ".apk"):
        if filename.endswith(ext):
            return ext
    return ""


def main(argv):
    dist = "dist"
    out = os.path.join(dist, "release-manifest.json")
    args = list(argv)
    while args:
        flag = args.pop(0)
        if flag == "--dist" and args:
            dist = args.pop(0)
        elif flag == "--out" and args:
            out = args.pop(0)
        else:
            raise SystemExit(f"unknown argument: {flag}")
    version = repo_version()
    commit = repo_commit()
    entries = []
    for filename in sorted(os.listdir(dist)):
        match = NAME_RE.match(filename)
        if not match:
            continue
        if match.group("version") != version:
            raise SystemExit(
                f"{filename}: version {match.group('version')} != package {version}"
            )
        key = (match.group("os"), match.group("arch"), match.group("musl") or "")
        target = TARGET_FOR.get(key)
        if target is None:
            raise SystemExit(f"{filename}: no target-triple mapping")
        path = os.path.join(dist, filename)
        entries.append(
            {
                "filename": filename,
                "platform": match.group("os"),
                "architecture": match.group("arch")
                + (match.group("musl") or ""),
                "target": target,
                "artifact_type": ARTIFACT_TYPE[ext_of(filename)],
                "development": match.group("dev") == "-dev",
                "version": version,
                "commit": commit,
                "sha256": sha256_of(path),
                "size_bytes": os.path.getsize(path),
            }
        )
    if not entries:
        raise SystemExit(f"no distribution archives found in {dist}/")
    manifest = {
        "project": "RXScan",
        "version": version,
        "commit": commit,
        "artifacts": entries,
    }
    with open(out, "w", encoding="utf-8") as handle:
        json.dump(manifest, handle, indent=2)
        handle.write("\n")
    print(f"wrote {out} ({len(entries)} artifacts)")


if __name__ == "__main__":
    main(sys.argv[1:])
