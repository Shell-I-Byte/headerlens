#!/usr/bin/env python3
"""Fail-closed pre-extraction check of a sealed HeaderLens source ZIP.

Only the release sealer's one-root, regular-file ZIP shape is accepted. This
binds archive *membership* to the internal SHA-256 manifest. The manifest is
not signed, so verify a trusted external release SHA-256 separately.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import stat
import sys
import unicodedata
import zipfile
from pathlib import Path

MANIFEST = "RELEASE_SOURCE_MANIFEST_SHA256.json"
MAX_MEMBERS = 4096
MAX_FILE_SIZE = 128 * 1024 * 1024
MAX_TOTAL_SIZE = 512 * 1024 * 1024
MAX_MANIFEST_SIZE = 1024 * 1024
PORTABLE_COMPONENT = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}\Z")
HEX_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
# Win32 treats these names as devices even when followed by an extension.
# The superscript-digit variants are reserved by the Windows file namespace.
WINDOWS_DEVICE_STEMS = (
    {"con", "prn", "aux", "nul", "conin$", "conout$"}
    | {f"com{digit}" for digit in "123456789¹²³"}
    | {f"lpt{digit}" for digit in "123456789¹²³"}
)
WINDOWS_FORBIDDEN_CHARS = set('<>:"|?*')


class UnsafeArchive(ValueError):
    """Invalid ZIP shape, membership, or manifest-bound source integrity."""


def _portable_key(name: str) -> str:
    """Fold canonical Unicode aliases plus case for portable extraction checks.

    A validly manifested archive may contain NFC and NFD spellings that map
    to the same filesystem path on normalization-insensitive volumes.
    """
    return unicodedata.normalize("NFC", name.casefold())


def _pairs_unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise UnsafeArchive("duplicate JSON manifest key")
        result[key] = value
    return result


def _portable_part(part: str) -> bool:
    """Reject Windows device aliases and names that change on extraction.

    The ZIP is portable by contract, not merely safe to extract on Linux.
    These checks apply to *all* path components, including nested dirs.
    """
    if not part or part in (".", "..") or part.endswith((".", " ")):
        return False
    if any(ord(ch) < 32 or ord(ch) == 127 or ch in WINDOWS_FORBIDDEN_CHARS for ch in part):
        return False
    if part.casefold() == ".git":
        return False  # Never allow Git control metadata inside an extracted source tree.
    if part.split(".", 1)[0].casefold() in WINDOWS_DEVICE_STEMS:
        return False
    return True


def _safe_path(name: str, root: str) -> bool:
    if not name or name.startswith("/") or "\\" in name or "\x00" in name:
        return False
    parts = name.split("/")
    if len(parts) < 2 or parts[0] != root:
        return False
    return all(_portable_part(part) for part in parts)


def verify(archive: Path) -> dict[str, object]:
    with zipfile.ZipFile(archive, "r") as container:
        records = container.infolist()
        if not records or len(records) > MAX_MEMBERS:
            raise UnsafeArchive("invalid member count")
        names = [info.filename for info in records]
        if len(names) != len(set(names)):
            raise UnsafeArchive("duplicate ZIP member")
        if len({_portable_key(name) for name in names}) != len(names):
            raise UnsafeArchive("portable Unicode/casefold ZIP path collision")
        # Complete-filename comparisons alone miss *directory* case aliases:
        # docs/Foo/a and docs/foo/b silently merge when extracted on Windows.
        # A file/parent conflict (docs/Foo and docs/foo/bar) also cannot be
        # extracted portably, even when each file has a correct digest.
        casefold_directories = {}
        casefold_files = {_portable_key(name) for name in names}
        for name in names:
            parts = name.split("/")
            for index in range(1, len(parts)):
                directory = "/".join(parts[:index])
                key = _portable_key(directory)
                existing = casefold_directories.setdefault(key, directory)
                if existing != directory:
                    raise UnsafeArchive("portable Unicode/casefold ZIP directory collision")
                if key in casefold_files:
                    raise UnsafeArchive("ZIP member is also a parent directory")
        root = names[0].split("/", 1)[0]
        if not PORTABLE_COMPONENT.fullmatch(root) or not _portable_part(root):
            raise UnsafeArchive("unsafe ZIP root")
        total_size = 0
        for info in records:
            if not _safe_path(info.filename, root) or info.is_dir():
                raise UnsafeArchive("unsafe ZIP member path or directory")
            mode = info.external_attr >> 16
            if stat.S_IFMT(mode) not in (0, stat.S_IFREG):
                raise UnsafeArchive("non-regular ZIP member")
            if info.flag_bits & 0x1 or info.compress_type != zipfile.ZIP_DEFLATED:
                raise UnsafeArchive("encrypted or unsupported ZIP compression")
            if info.file_size > MAX_FILE_SIZE:
                raise UnsafeArchive("member exceeds size limit")
            total_size += info.file_size
            if total_size > MAX_TOTAL_SIZE:
                raise UnsafeArchive("archive exceeds size limit")
        manifest_name = root + "/" + MANIFEST
        if manifest_name not in names:
            raise UnsafeArchive("missing source manifest")
        manifest_info = container.getinfo(manifest_name)
        if manifest_info.file_size > MAX_MANIFEST_SIZE:
            raise UnsafeArchive("manifest exceeds size limit")
        manifest = json.loads(container.read(manifest_info), object_pairs_hook=_pairs_unique)
        if (not isinstance(manifest, dict) or manifest.get("algorithm") != "SHA-256" or
                not isinstance(manifest.get("files"), dict)):
            raise UnsafeArchive("invalid source manifest structure")
        expected = manifest["files"]
        if len(expected) + 1 != len(names):
            raise UnsafeArchive("member count differs from manifest")
        actual = {name[len(root) + 1:] for name in names if name != manifest_name}
        if actual != set(expected):
            raise UnsafeArchive("ZIP contents differ from source manifest")
        for rel, digest in expected.items():
            if (not isinstance(rel, str) or not _safe_path(root + "/" + rel, root) or
                    rel == MANIFEST or not isinstance(digest, str) or
                    not HEX_SHA256.fullmatch(digest)):
                raise UnsafeArchive("invalid manifest entry")
            hasher = hashlib.sha256()
            with container.open(root + "/" + rel) as member:
                while chunk := member.read(1024 * 1024):
                    hasher.update(chunk)
            if hasher.hexdigest() != digest:
                raise UnsafeArchive("source manifest digest mismatch")
        with archive.open("rb") as handle:
            archive_digest = hashlib.file_digest(handle, "sha256").hexdigest()
        return {"root": root, "members": len(records), "hashed": len(expected),
                "archive_sha256": archive_digest}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("archive", type=Path)
    args = parser.parse_args()
    try:
        outcome = verify(args.archive)
    except (OSError, ValueError, zipfile.BadZipFile, RuntimeError, EOFError) as exc:
        print(f"FAIL: source archive rejected: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 1
    print(f"PASS: sealed source archive root={outcome['root']} members={outcome['members']} "
          f"hashed={outcome['hashed']} sha256={outcome['archive_sha256']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
