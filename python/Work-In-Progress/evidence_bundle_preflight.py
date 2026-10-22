#!/usr/bin/env python3
"""Read-only ZIP preflight for incident-response evidence bundles.

WIP prototype: audits ZIP metadata, not file content or evidentiary validity.
Python 3.9+; standard library only. Never extracts or changes an input archive.
"""

import argparse
import hashlib
import json
import re
import stat
import sys
import unicodedata
import zipfile
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

BUILD = "WIP-IR-ZIP-PREFLIGHT-0.1"
CHUNK_SIZE = 1024 * 1024


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(CHUNK_SIZE), b""):
            digest.update(chunk)
    return digest.hexdigest()


def unsafe_path_reasons(name: str) -> list[str]:
    normalized = name.replace("\\", "/")
    reasons = []
    if normalized.startswith("/") or re.match(r"^[A-Za-z]:", normalized):
        reasons.append("absolute_or_drive_path")
    if ".." in normalized.split("/"):
        reasons.append("parent_directory_segment")
    if any(ord(char) < 32 for char in name):
        reasons.append("control_character")
    if ":" in normalized:
        reasons.append("colon_in_path")
    return reasons


def inspect_archive(path: Path, ratio_limit: float, size_limit: int) -> dict:
    before = sha256_file(path)
    issues = []
    entries = []
    canonical_names = {}
    totals = Counter()

    def issue(severity: str, code: str, entry: str | None, detail: str):
        issues.append({"severity": severity, "code": code,
                       "entry": entry, "detail": detail})

    with zipfile.ZipFile(path, "r", allowZip64=True) as archive:
        for info in archive.infolist():
            name = info.filename
            totals["entries"] += 1
            totals["uncompressed_bytes"] += info.file_size
            totals["compressed_bytes"] += info.compress_size
            if not info.is_dir():
                totals["files"] += 1

            for reason in unsafe_path_reasons(name):
                issue("ERROR", "UNSAFE_PATH", name, reason)

            canonical = unicodedata.normalize("NFC", name.replace("\\", "/")).casefold()
            if canonical in canonical_names:
                issue("ERROR", "DUPLICATE_PATH", name,
                      f"Collides with ZIP entry: {canonical_names[canonical]}")
            else:
                canonical_names[canonical] = name

            is_symlink = (info.create_system == 3 and
                          stat.S_IFMT(info.external_attr >> 16) == stat.S_IFLNK)
            if is_symlink:
                issue("WARN", "SYMLINK_ENTRY", name,
                      "Archive contains a symbolic-link entry")
            if info.flag_bits & 0x1:
                issue("WARN", "ENCRYPTED_ENTRY", name,
                      "Entry cannot be reviewed without a password")

            ratio = (info.file_size / max(info.compress_size, 1)) if info.file_size else 0.0
            if ratio > ratio_limit:
                issue("WARN", "HIGH_COMPRESSION_RATIO", name,
                      f"Ratio {ratio:.1f} exceeds limit {ratio_limit:g}")
            if info.file_size > size_limit:
                issue("WARN", "LARGE_ENTRY", name,
                      f"Uncompressed bytes {info.file_size} exceed {size_limit}")

            entries.append({
                "name": name,
                "directory": info.is_dir(),
                "uncompressed_bytes": info.file_size,
                "compressed_bytes": info.compress_size,
                "crc32_declared": f"{info.CRC:08x}",
                "encrypted": bool(info.flag_bits & 0x1),
                "symlink": is_symlink,
            })

    if totals["uncompressed_bytes"] > size_limit:
        issue("WARN", "LARGE_ARCHIVE_EXPANSION", None,
              f"Total uncompressed bytes {totals['uncompressed_bytes']} exceed {size_limit}")

    after = sha256_file(path)
    if before != after:
        issue("ERROR", "ARCHIVE_CHANGED", None,
              "Archive SHA-256 changed during the audit")

    outcome = ("ERROR" if any(i["severity"] == "ERROR" for i in issues)
               else "WARN" if issues else "PASS")
    return {
        "build": BUILD,
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "archive": str(path),
        "archive_size_bytes": path.stat().st_size,
        "sha256_before": before,
        "sha256_after": after,
        "status": outcome,
        "summary": dict(totals),
        "issues": issues,
        "entries": entries,
        "limitations": [
            "ZIP directory metadata only; entry contents are not opened or hashed",
            "Declared CRC-32 and size values are not independently verified",
            "Does not determine malware, authenticity, or chain of custody",
            "Filenames and paths in this report may contain sensitive information",
        ],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("archive", type=Path, help="Existing ZIP archive to inspect")
    parser.add_argument("--output", type=Path,
                        help="JSON report destination (default: ZIP path + .preflight.json)")
    parser.add_argument("--ratio-limit", type=float, default=100.0,
                        help="Warn above this declared uncompressed/compressed ratio")
    parser.add_argument("--size-limit-gib", type=float, default=10.0,
                        help="Warn above this declared entry/total expansion size")
    args = parser.parse_args()

    report_path = args.output or Path(str(args.archive) + ".preflight.json")
    if not args.archive.is_file():
        parser.error("archive does not exist or is not a regular file")
    if args.archive.resolve() == report_path.resolve():
        parser.error("report destination must differ from input archive")
    if not (0 < args.ratio_limit < float("inf")) or not (0 < args.size_limit_gib < float("inf")):
        parser.error("limits must be finite positive numbers")

    try:
        report = inspect_archive(args.archive, args.ratio_limit,
                                 int(args.size_limit_gib * (1024 ** 3)))
        # No automatic parent directory creation; avoid unexpected writes.
        with report_path.open("w", encoding="utf-8", newline="\n") as destination:
            json.dump(report, destination, indent=2, ensure_ascii=False)
            destination.write("\n")
    except (OSError, zipfile.BadZipFile, zipfile.LargeZipFile, ValueError) as error:
        print(f"ERROR | Preflight failed: {error}", file=sys.stderr)
        return 2

    print(f"{report['status']} | Files={report['summary'].get('files', 0)} "
          f"Issues={len(report['issues'])} Report={report_path}")
    # WARN is distinct from a blocked/unsafe ZIP. Preserve machine-readable status.
    return 2 if report["status"] == "ERROR" else 1 if report["status"] == "WARN" else 0


if __name__ == "__main__":
    sys.exit(main())
