#!/usr/bin/env python3
"""Correct one explicit POSIX permission baseline, with dry-run by default."""

# NAME: Linux File Permissions Remediation
# AUTHORED BY: Cogan Goldwater
# TYPE: Remediation
# SCOPE: Linux/POSIX files and directories
# INPUTS: --path PATH --mode OCTAL [--type file|directory] [--apply]
# OUTPUT TOKENS: RESULT / NO_ACTION / ERROR
# WRITES: Only the selected target's permission bits when --apply is supplied
# EXIT CODE: Always 0 (token-driven automation)
# DESCRIPTION: Never follows symlinks; uses descriptor-based chmod on Linux.

import argparse
import os
import re
import stat
from pathlib import Path


def parse_mode(value: str) -> int:
    if not re.fullmatch(r"[0-7]{3,4}", value):
        raise argparse.ArgumentTypeError("mode must be 3 or 4 octal digits (example: 0600)")
    return int(value, 8)


def remediate(path: Path, desired_mode: int, expected_type: str, apply: bool) -> tuple[str, str]:
    if os.name != "posix" or not hasattr(os, "O_NOFOLLOW"):
        return "ERROR", "Requires POSIX with O_NOFOLLOW support (Linux recommended)"

    flags = os.O_RDONLY | os.O_NOFOLLOW
    if expected_type == "directory":
        flags |= getattr(os, "O_DIRECTORY", 0)
    else:
        flags |= getattr(os, "O_NONBLOCK", 0)

    fd = None
    try:
        fd = os.open(path, flags)
        before = os.fstat(fd)
        if expected_type == "file" and not stat.S_ISREG(before.st_mode):
            return "ERROR", "Expected a regular file; no change made"
        if expected_type == "directory" and not stat.S_ISDIR(before.st_mode):
            return "ERROR", "Expected a directory; no change made"

        current_mode = stat.S_IMODE(before.st_mode)
        details = f"Path={path} Type={expected_type} Before={current_mode:04o} Required={desired_mode:04o}"
        if current_mode == desired_mode:
            return "NO_ACTION", f"Already compliant | {details}"
        if not apply:
            return "NO_ACTION", f"DryRun=True ChangeRequired=True | {details}"

        # Change the opened object, not a pathname that could become a symlink.
        os.fchmod(fd, desired_mode)
        after = os.fstat(fd)
        path_after = path.lstat()
        if ((after.st_dev, after.st_ino) != (before.st_dev, before.st_ino)
                or (path_after.st_dev, path_after.st_ino) != (before.st_dev, before.st_ino)):
            return "ERROR", "Target identity changed during operation; inspect manually"
        if stat.S_IMODE(after.st_mode) != desired_mode:
            return "ERROR", f"Verification failed: observed {stat.S_IMODE(after.st_mode):04o}"
        return "RESULT", f"Permissions corrected and verified | {details} After={desired_mode:04o}"
    except OSError as exc:
        return "ERROR", f"Permission operation failed ({type(exc).__name__}): {exc.strerror or exc}"
    finally:
        if fd is not None:
            os.close(fd)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--path", required=True, type=Path)
    parser.add_argument("--mode", required=True, type=parse_mode)
    parser.add_argument("--type", choices=("file", "directory"), default="file")
    parser.add_argument("--apply", action="store_true", help="Apply the change (default: dry-run only)")
    args = parser.parse_args()
    token, message = remediate(args.path.expanduser().absolute(), args.mode, args.type, args.apply)
    print(f"{token} | {message}")


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        print(f"ERROR | Unexpected remediation failure: {type(exc).__name__}: {exc}")
