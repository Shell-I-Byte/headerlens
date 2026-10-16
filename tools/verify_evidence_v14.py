#!/usr/bin/env python3
"""Independent HeaderLens v14 observation digest verifier, Python stdlib only.

A matching digest is NOT an authenticated claim about findings or scope.
"""
import argparse
import json
import sys
from pathlib import Path
from verify_evidence_v13 import VerificationError, reject_duplicate, reject_constant, verify


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("json_file", type=Path)
    args = parser.parse_args()
    try:
        if args.json_file.stat().st_size > 64 * 1024 * 1024:
            raise VerificationError("file exceeds 64 MiB verifier limit")
        obj = json.loads(args.json_file.read_text(encoding="utf-8"), object_pairs_hook=reject_duplicate, parse_constant=reject_constant)
        matched, calculated, stored = verify(obj, required_schema="headerlens.result/v14")
    except (VerificationError, OSError, UnicodeError, ValueError, TypeError, KeyError) as exc:
        print("INVALID v14 evidence object: " + str(exc), file=sys.stderr)
        return 2
    if not matched:
        print("MISMATCH expected=" + str(stored) + " computed=" + calculated, file=sys.stderr)
        return 1
    print("MATCH v14 observation digest: " + calculated)
    print("NOTICE: findings, timestamp, duration, tool_version, and authorization are NOT hash-bound; SHA-256 is NOT a signature.")
    return 0

if __name__ == "__main__":
    sys.exit(main())
