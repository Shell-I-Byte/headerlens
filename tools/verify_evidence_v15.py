#!/usr/bin/env python3
"""Independent HeaderLens v15 SHA-256 observation verifier (not a signature).

v15 preserves the normalized v14 digest projection; default authentication
field-value redaction changes the observed value and necessitates a new
version identity. Authenticated provenance is deliberately out of scope.
"""
import argparse
import base64
import json
import sys
from pathlib import Path
from verify_evidence_v13 import VerificationError, reject_duplicate, reject_constant, verify

_AUTH_FIELDS = frozenset((
    "authentication-info", "proxy-authentication-info", "authorization",
    "proxy-authorization", "www-authenticate", "proxy-authenticate",
))
_AUTH_MARKER = "<redacted authentication field>"
_AUTH_MARKER_B64 = base64.b64encode(_AUTH_MARKER.encode("utf-8")).decode("ascii")


def check_auth_redaction(section):
    """Check a v15 producer invariant, independent of digest consistency.

    A checksum alone cannot authenticate a producer; this catches a strictly
    narrower error: a self-consistent JSON object that claims default auth
    redaction yet visibly preserves values or an opaque byte mirror.
    """
    if not isinstance(section, dict) or type(section.get("headers_redacted")) is not bool:
        raise VerificationError("invalid v15 redaction indicator")
    if not section["headers_redacted"]:
        return
    headers = section.get("headers", {})
    mirrors = section.get("header_bytes_b64", {})
    if not isinstance(headers, dict) or not isinstance(mirrors, dict):
        raise VerificationError("invalid v15 header maps")
    for key, values in headers.items():
        if key.casefold() in _AUTH_FIELDS:
            if not isinstance(values, list) or any(value != _AUTH_MARKER for value in values):
                raise VerificationError("v15 redaction invariant violated in auth header")
    for key, values in mirrors.items():
        if key.casefold() in _AUTH_FIELDS:
            if not isinstance(values, list) or any(value != _AUTH_MARKER_B64 for value in values):
                raise VerificationError("v15 redaction invariant violated in opaque auth bytes")


def verify_v15(result):
    """Check v15 digest *and* semantic redaction invariants; NOT a signature."""
    digest = verify(result, required_schema="headerlens.result/v15")
    check_auth_redaction(result)
    for group in ("redirect_responses", "interim_responses"):
        for section in result.get(group, ()):
            check_auth_redaction(section)
    return digest


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("json_file", type=Path)
    args = parser.parse_args()
    try:
        if args.json_file.stat().st_size > 64 * 1024 * 1024:
            raise VerificationError("file exceeds 64 MiB verifier limit")
        obj = json.loads(args.json_file.read_text(encoding="utf-8"),
                         object_pairs_hook=reject_duplicate,
                         parse_constant=reject_constant)
        matched, calculated, stored = verify_v15(obj)
    except (VerificationError, OSError, UnicodeError, ValueError, TypeError, KeyError) as exc:
        print("INVALID v15 evidence object: " + str(exc), file=sys.stderr)
        return 2
    if not matched:
        print("MISMATCH expected=" + str(stored) + " computed=" + calculated, file=sys.stderr)
        return 1
    print("MATCH v15 observation digest: " + calculated)
    print("NOTICE: checksum is NOT a signature; findings/time/tool_version/authorization are not bound.")
    return 0

if __name__ == "__main__":
    sys.exit(main())
