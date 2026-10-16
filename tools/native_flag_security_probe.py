#!/usr/bin/env python3
"""Offline compiled-binary regression for BUG-HL-075.

Usage: python3 tools/native_flag_security_probe.py /absolute/path/to/headerlens
Performs no HTTP requests and does not require external Python packages.
"""
from __future__ import annotations

import pathlib
import subprocess
import sys


def run(exe: pathlib.Path, arg: str):
    return subprocess.run([str(exe), arg], capture_output=True, timeout=5, check=False)


def main() -> int:
    if len(sys.argv) != 2:
        raise SystemExit("usage: native_flag_security_probe.py EXECUTABLE")
    exe = pathlib.Path(sys.argv[1]).resolve()
    if not exe.is_file():
        raise SystemExit("missing executable")

    version = run(exe, "-version")
    assert version.returncode == 0 and version.stdout.decode().strip() == "0.1.21-rc11", version
    print("PASS compiled version")

    # Positive help contract: informational flags must not fail CI/shell pipelines.
    for help_flag in ("-h", "-help", "--help"):
        completed = run(exe, help_flag)
        assert completed.returncode == 0, (help_flag, completed.returncode)
        assert b"Usage: headerlens" in completed.stderr, help_flag
        assert b"invalid command-line option" not in completed.stderr, help_flag
        print("PASS help", help_flag)

    for name, arg, unsafe in [
        ("newline", "-not-valid\nCI-RESULT:PASS", b"\nCI-RESULT:PASS"),
        ("ansi", "-not-valid\x1b[32mPASS", b"\x1b"),
        ("bidi", "-not-valid\u202eFLIP", "\u202e".encode("utf-8")),
        ("malformed_value", "-timeout=abc\nCI-RESULT:PASS", b"\nCI-RESULT:PASS"),
    ]:
        completed = run(exe, arg)
        assert completed.returncode == 2, (name, completed.returncode)
        assert not completed.stdout, (name, completed.stdout)
        assert unsafe not in completed.stderr, (name, completed.stderr)
        assert b"Usage: headerlens" in completed.stderr, (name, completed.stderr)
        assert b"-max-header-bytes" in completed.stderr, (name, completed.stderr)
        print("PASS", name)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
