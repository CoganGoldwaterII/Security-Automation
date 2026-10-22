#!/usr/bin/env python3
"""Evaluate a POSIX file/directory permission baseline (read-only)."""

# NAME: Linux File Permissions Evaluation
# AUTHORED BY: Cogan Goldwater
# TYPE: Evaluation
# SCOPE: Linux/POSIX files and directories
# INPUTS: --path PATH --mode OCTAL [--type file|directory]
# OUTPUT TOKENS: TRIGGER / NO_ACTION / ERROR
# WRITES: None
# EXIT CODE: Always 0 (token-driven automation)
# DESCRIPTION: Check the exact permission bits on a single explicit target.

import argparse
import os
import re
import stat
from pathlib import Path


def parse_mode(value: str) -> int:
    if not re.fullmatch(r"[0-7]{3,4}", value):
        raise argparse.ArgumentTypeError("mode must be 3 or 4 octal digits (example: 0600)")
    mode = int(value, 8)
    if mode > 0o7777:
        raise argparse.ArgumentTypeError("mode exceeds the POSIX permission range")
    return mode


def evaluate(path: Path, desired_mode: int, expected_type: str) -> tuple[str, str]:
    if os.name != "posix":
        return "ERROR", "POSIX permissions are required; this script is not for Windows ACLs"

    try:
        info = path.lstat()  # Do not follow symlinks.
    except OSError as exc:
        return "ERROR", f"Cannot inspect target ({type(exc).__name__}): {exc.strerror or exc}"

    if stat.S_ISLNK(info.st_mode):
        return "ERROR", "Refusing a symbolic link"
    if expected_type == "file" and not stat.S_ISREG(info.st_mode):
        return "ERROR", "Expected a regular file"
    if expected_type == "directory" and not stat.S_ISDIR(info.st_mode):
        return "ERROR", "Expected a directory"

    actual = stat.S_IMODE(info.st_mode)
    details = f"Path={path} Type={expected_type} Actual={actual:04o} Required={desired_mode:04o}"
    if actual == desired_mode:
        return "NO_ACTION", f"Permissions compliant | {details}"
    return "TRIGGER", f"Permission drift detected | {details}"


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--path", required=True, type=Path, help="Explicit target path")
    parser.add_argument("--mode", required=True, type=parse_mode, help="Required POSIX mode, e.g. 0600")
    parser.add_argument("--type", choices=("file", "directory"), default="file")
    args = parser.parse_args()

    token, message = evaluate(args.path.expanduser().absolute(), args.mode, args.type)
    print(f"{token} | {message}")


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        print(f"ERROR | Unexpected evaluation failure: {type(exc).__name__}: {exc}")
