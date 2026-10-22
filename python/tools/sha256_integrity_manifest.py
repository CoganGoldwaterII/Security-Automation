#!/usr/bin/env python3
"""Create or verify SHA-256 manifests of directory trees without external packages."""

# NAME: SHA-256 File Integrity Manifest Tool
# AUTHORED BY: Cogan Goldwater
# TYPE: Standalone Tool
# SCOPE: Windows, macOS, Linux (Python 3.9+)
# INPUTS: create|verify --root DIRECTORY --manifest FILE
# OUTPUT TOKENS: RESULT / NO_ACTION / TRIGGER / ERROR
# WRITES: JSON manifest in create mode; verify mode is read-only
# EXIT CODE: Always 0 (token-driven automation)
# SECURITY: Refuses symlinks to avoid silently omitting redirected content.

import argparse
import hashlib
import json
import os
import stat
import tempfile
from pathlib import Path

SCHEMA_VERSION = 1
CHUNK_SIZE = 1024 * 1024
SKIPPED_DIRS = {".git", "__pycache__"}


def sha256_file(path: Path) -> str:
    # O_NOFOLLOW prevents a symlink swap during open on platforms that support it.
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    try:
        original = os.fstat(descriptor)
        if not stat.S_ISREG(original.st_mode):
            raise ValueError(f"File is no longer regular: {path}")
        digest = hashlib.sha256()
        with os.fdopen(descriptor, "rb", closefd=False) as source:
            while data := source.read(CHUNK_SIZE):
                digest.update(data)
        current = path.lstat()
        if (original.st_dev, original.st_ino) != (current.st_dev, current.st_ino):
            raise ValueError(f"File identity changed while hashing: {path}")
        return digest.hexdigest()
    finally:
        os.close(descriptor)


def snapshot(root: Path, manifest_path: Path) -> dict[str, str]:
    records: dict[str, str] = {}
    def fail_walk(exc: OSError) -> None:
        raise exc  # Never report success when a directory was unreadable.

    for base, dirs, files in os.walk(root, followlinks=False, onerror=fail_walk):
        base_path = Path(base)
        for name in dirs:
            candidate = base_path / name
            if candidate.is_symlink():
                raise ValueError(f"Symbolic link directory not supported: {candidate}")
        dirs[:] = sorted(name for name in dirs if name not in SKIPPED_DIRS)
        for name in sorted(files):
            path = base_path / name
            if path == manifest_path:
                continue  # Never include the output manifest in its own checksum set.
            info = path.lstat()
            if stat.S_ISLNK(info.st_mode):
                raise ValueError(f"Symbolic link file not supported: {path}")
            if not stat.S_ISREG(info.st_mode):
                raise ValueError(f"Non-regular file not supported: {path}")
            relative = path.relative_to(root).as_posix()
            records[relative] = sha256_file(path)
    return dict(sorted(records.items()))


def load_manifest(path: Path) -> dict[str, str]:
    with path.open("r", encoding="utf-8") as stream:
        data = json.load(stream)
    if (not isinstance(data, dict) or data.get("schema_version") != SCHEMA_VERSION
            or data.get("algorithm") != "sha256" or not isinstance(data.get("files"), dict)):
        raise ValueError("Invalid manifest schema or unsupported algorithm")
    for name, checksum in data["files"].items():
        if (not isinstance(name, str) or not name or name.startswith("/")
                or "\\" in name or any(part in ("", ".", "..") for part in name.split("/"))
                or not isinstance(checksum, str) or len(checksum) != 64
                or any(char not in "0123456789abcdef" for char in checksum)):
            raise ValueError("Manifest contains an unsafe path or invalid SHA-256 value")
    return data["files"]


def write_manifest(path: Path, records: dict[str, str]) -> None:
    document = {"schema_version": SCHEMA_VERSION, "algorithm": "sha256", "files": records}
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(prefix=".integrity-", suffix=".tmp", dir=path.parent)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as stream:
            json.dump(document, stream, indent=2, sort_keys=True)
            stream.write("\n")
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def run(command: str, root: Path, manifest: Path) -> tuple[str, str]:
    if not root.is_dir():
        return "ERROR", f"Root directory not found: {root}"
    if root.is_symlink():
        return "ERROR", "Root cannot be a symbolic link"
    if manifest.is_symlink():
        return "ERROR", "Manifest cannot be a symbolic link"
    if command == "create" and manifest.exists():
        return "ERROR", "Manifest exists; refusing to overwrite an existing integrity baseline"
    if command == "verify":
        expected = load_manifest(manifest)
        actual = snapshot(root, manifest)
        added = sorted(set(actual) - set(expected))
        missing = sorted(set(expected) - set(actual))
        modified = sorted(k for k in expected.keys() & actual.keys() if expected[k] != actual[k])
        if added or missing or modified:
            # Names are included to make a useful, inspectable incident report.
            details = {"added": added, "missing": missing, "modified": modified}
            return "TRIGGER", json.dumps(details, separators=(",", ":"))
        return "NO_ACTION", f"Integrity verified | Files={len(expected)} Root={root}"
    actual = snapshot(root, manifest)
    write_manifest(manifest, actual)
    return "RESULT", f"Baseline generated | Files={len(actual)} Manifest={manifest}"


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("create", "verify"))
    parser.add_argument("--root", required=True, type=Path)
    parser.add_argument("--manifest", required=True, type=Path)
    args = parser.parse_args()
    root = args.root.expanduser().absolute()
    manifest = args.manifest.expanduser().absolute()
    token, message = run(args.command, root, manifest)
    print(f"{token} | {message}")


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"ERROR | Integrity operation failed: {type(exc).__name__}: {exc}")
    except Exception as exc:
        print(f"ERROR | Unexpected failure: {type(exc).__name__}: {exc}")
