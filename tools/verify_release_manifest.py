"""Offline source-manifest validation (not a runtime feature).

Normal checkout mode ignores developer-generated Python caches. Strict sealed
mode rejects ANY extra files, including those under __pycache__, so an archive
cannot hide untracked payloads in excluded development-only paths.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

MANIFEST = "RELEASE_SOURCE_MANIFEST_SHA256.json"


def eligible(relative: str) -> bool:
    parts = Path(relative).parts
    return (relative != MANIFEST and ".git" not in parts and
            "__pycache__" not in parts and not relative.endswith(".pyc") and
            not relative.endswith(".pyo") and relative != ".DS_Store")


def validate(root: Path, *, sealed: bool = False) -> list[str]:
    issues = []
    try:
        record = json.loads((root / MANIFEST).read_text(encoding="utf-8"))
        if record.get("algorithm") != "SHA-256" or not isinstance(record.get("files"), dict):
            return ["invalid manifest format"]
        expected = record["files"]
    except (OSError, json.JSONDecodeError):
        return ["manifest unavailable or invalid"]

    actual = {}
    for f in root.rglob("*"):
        rel = f.relative_to(root).as_posix()
        if f.is_symlink():
            if sealed or eligible(rel):
                issues.append(f"symlink in source archive: {rel}")
            continue
        if not f.is_file():
            continue
        if not eligible(rel):
            if sealed and rel != MANIFEST:
                issues.append(f"non-source file in sealed archive: {rel}")
            continue
        actual[rel] = hashlib.sha256(f.read_bytes()).hexdigest()
    for name, sha in expected.items():
        if (not isinstance(name, str) or not eligible(name) or
                Path(name).is_absolute() or ".." in Path(name).parts):
            issues.append(f"unsafe/non-source manifest entry: {name!r}")
        elif not isinstance(sha, str) or len(sha) != 64:
            issues.append(f"invalid hash entry: {name!r}")
    for name in sorted(actual.keys() - expected.keys()):
        issues.append(f"unlisted source: {name}")
    for name in sorted(expected.keys() - actual.keys()):
        issues.append(f"missing source: {name}")
    for name in sorted(expected.keys() & actual.keys()):
        if expected[name] != actual[name]:
            issues.append(f"digest mismatch: {name}")
    return issues


if __name__ == "__main__":
    import argparse
    import sys
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("root", nargs="?", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--sealed", action="store_true", help="reject all extra non-source files in extracted release ZIP (not a Git checkout)")
    args = parser.parse_args()
    root = args.root.resolve()
    errors = validate(root, sealed=args.sealed)
    for e in errors:
        print(e, file=sys.stderr)
    print("PASS: source manifest matches clean source tree" if not errors else "FAIL: source manifest mismatch")
    raise SystemExit(bool(errors))
