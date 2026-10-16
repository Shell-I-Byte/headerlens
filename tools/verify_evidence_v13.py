#!/usr/bin/env python3
"""Independent HeaderLens v13 observation-digest verifier (Python stdlib only).

WARNING: the SHA-256 digest authenticates NOTHING by itself. It does not bind
findings, timestamp, tool version, policies, or scanning authorizations. It is
ONLY a consistency check for a specified subset of normalized observations.
"""
import argparse
import hashlib
import json
import sys
from pathlib import Path

# These ordered fields mirror the frozen Go v13 evidenceHash wire contract.
TOP = ("schema_version", "tool", "target", "final_url", "status_code", "http_version", "headers", "header_bytes_b64", "headers_redacted", "tls", "tls_verification", "http_framing", "redirect_chain", "redirect_responses", "interim_responses", "redirect_blocked")
TLS = ("version", "cipher_suite", "server_name", "negotiated_protocol", "cert_subject", "cert_issuer", "cert_not_before", "cert_not_after", "cert_dns_names", "cert_sha256", "verified_chains")
TLS_ALWAYS = frozenset(("cert_not_before", "cert_not_after"))
TLS_VERIFY = ("verified", "error_kind")
FRAMING = ("content_length", "transfer_encoding", "connection_close", "trailer_names")
REDIRECT = ("url", "status_code", "http_version", "headers", "header_bytes_b64", "headers_redacted", "tls", "tls_verification", "http_framing")
INTERIM = ("request_index", "url", "status_code", "headers", "header_bytes_b64", "headers_redacted")
BLOCKED = ("url",)
ALLOWED_TOP = frozenset(TOP) | frozenset(("tool_version", "duration_ms", "findings", "evidence_sha256", "scanned_at"))

class VerificationError(ValueError):
    pass


def reject_duplicate(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise VerificationError("duplicate JSON key (field name suppressed)")
        result[key] = value
    return result


def reject_constant(s):
    raise VerificationError("non-JSON numeric value: " + s)


def check_obj(obj, keys, where, additional=False):
    if not isinstance(obj, dict):
        raise VerificationError(where + " must be a JSON object")
    unexpected = set(obj) - set(keys)
    if unexpected and not additional:
        raise VerificationError(where + ": unsupported JSON field (field names suppressed)")


def make_fields(obj, fields, *, always=(), where="object", required=(), allowed_extra=()):
    check_obj(obj, set(fields) | set(allowed_extra), where)
    for k in required:
        if k not in obj:
            raise VerificationError(where + ": missing required " + k)
    out = {}
    for k in fields:
        if k not in obj:
            continue
        value = obj[k]
        # Implements Go's omitempty for v13 string/slice/map fields. Go's
        # time.Time MarshalJSON struct fields are NOT omitted when zero.
        if k not in always and (value is None or value == "" or value == [] or value == {}):
            continue
        out[k] = value
    return out


def string_map(value, where):
    if not isinstance(value, dict):
        raise VerificationError(where + " must be a map")
    out = {}
    for name in sorted(value):
        vals = value[name]
        if not isinstance(name, str) or not isinstance(vals, list) or any(not isinstance(v, str) for v in vals):
            raise VerificationError(where + " keys must be strings and values string arrays")
        out[name] = vals
    return out


def tls_object(obj):
    out = make_fields(obj, TLS, always=TLS_ALWAYS, where="tls")
    for field in TLS_ALWAYS:
        if field not in out:
            raise VerificationError("tls lacks serialized time: " + field)
    return out


def verification_object(obj):
    return make_fields(obj, TLS_VERIFY, always=("verified",), required=("verified",), where="tls_verification")


def framing_object(obj):
    return make_fields(obj, FRAMING, always=("content_length", "connection_close"), required=("content_length", "connection_close"), where="http_framing")


def common_evidence(obj, fields, where):
    extra = ALLOWED_TOP - set(TOP) if where == "result" else (("findings",) if where in ("redirect_response", "interim_response") else ())
    out = make_fields(obj, fields, always=("schema_version", "tool", "target", "final_url", "status_code", "http_version", "headers", "headers_redacted", "url", "request_index"), where=where, allowed_extra=extra)
    if "headers" not in out:
        raise VerificationError(where + ": missing headers")
    out["headers"] = string_map(out["headers"], where + ".headers")
    if "header_bytes_b64" in out:
        out["header_bytes_b64"] = string_map(out["header_bytes_b64"], where + ".header_bytes_b64")
    if "tls" in out:
        out["tls"] = tls_object(out["tls"])
    if "tls_verification" in out:
        out["tls_verification"] = verification_object(out["tls_verification"])
    if "http_framing" in out:
        out["http_framing"] = framing_object(out["http_framing"])
    return out


def digest_object(result, required_schema="headerlens.result/v13"):
    check_obj(result, ALLOWED_TOP, "result")
    if result.get("schema_version") != required_schema:
        raise VerificationError("requires exactly " + required_schema)
    if "evidence_sha256" not in result:
        raise VerificationError("evidence_sha256 is missing")
    out = common_evidence(result, TOP, "result")
    if "redirect_responses" in out:
        out["redirect_responses"] = [common_evidence(x, REDIRECT, "redirect_response") for x in out["redirect_responses"]]
    if "interim_responses" in out:
        out["interim_responses"] = [common_evidence(x, INTERIM, "interim_response") for x in out["interim_responses"]]
    if "redirect_blocked" in out:
        out["redirect_blocked"] = make_fields(out["redirect_blocked"], BLOCKED, always=("url",), where="redirect_blocked", required=("url",), allowed_extra=("reason",))
    return out


def go_json_marshal(value):
    # Go encoding/json.Marshal escapes HTML characters and U+2028/U+2029 by
    # default. All map keys are sorted; struct field order follows TOP etc.
    serialized = json.dumps(value, ensure_ascii=False, separators=(",", ":"), allow_nan=False)
    for ch, repl in (("&", "\\u0026"), ("<", "\\u003c"), (">", "\\u003e"), ("\u2028", "\\u2028"), ("\u2029", "\\u2029")):
        serialized = serialized.replace(ch, repl)
    return serialized.encode("utf-8")


def verify(result, required_schema="headerlens.result/v13"):
    obj = digest_object(result, required_schema=required_schema)
    calculated = hashlib.sha256(go_json_marshal(obj)).hexdigest()
    recorded = result["evidence_sha256"]
    # This comes from untrusted evidence. Never echo arbitrary supplied values
    # through the mismatch diagnostic; accept only the SHA-256 wire format.
    if (not isinstance(recorded, str) or len(recorded) != 64 or
            any(c not in "0123456789abcdef" for c in recorded)):
        raise VerificationError("evidence_sha256 must be 64 lowercase hex characters")
    return calculated == recorded, calculated, recorded


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("json_file", type=Path)
    args = parser.parse_args()
    try:
        if args.json_file.stat().st_size > 64 * 1024 * 1024:
            raise VerificationError("file exceeds 64 MiB verifier limit")
        obj = json.loads(args.json_file.read_text(encoding="utf-8"), object_pairs_hook=reject_duplicate, parse_constant=reject_constant)
        matched, calculated, stored = verify(obj)
    except (VerificationError, OSError, UnicodeError, ValueError, TypeError, KeyError) as exc:
        print("INVALID v13 evidence object: " + str(exc), file=sys.stderr)
        return 2
    if not matched:
        print("MISMATCH expected=" + str(stored) + " computed=" + calculated, file=sys.stderr)
        return 1
    print("MATCH v13 observation digest: " + calculated)
    print("NOTICE: findings, timestamp, duration, tool_version, and authorization are NOT hash-bound; SHA-256 is NOT a signature.")
    return 0

if __name__ == "__main__":
    sys.exit(main())
