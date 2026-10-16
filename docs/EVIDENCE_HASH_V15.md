> Current public release and Mac validation status: [README](../README.md) and [MACOS_QUALIFICATION.md](MACOS_QUALIFICATION.md). Historical run references in this technical document do not describe the current publication status.

# HeaderLens v15 — authentication field redaction and normalized observation digests

**Current producer:** HeaderLens v0.1.18 RC; **schema identity:** `headerlens.result/v15`. This document extends the frozen v13 ordered projection and v14's two-pass UTF-8 JSON normalization. For exact digest byte-level rules use `docs/EVIDENCE_HASH_V13.md` plus the amendment `docs/EVIDENCE_HASH_V14.md`, substituting schema identity `headerlens.result/v15`.

## Normative v15 observation semantic change

When `headers_redacted=true`, the following standard HTTP response header names, **case-insensitively**, have every value replaced by the exact UTF-8 string `<redacted authentication field>`: `Authentication-Info`, `Proxy-Authentication-Info`, `Authorization`, `Proxy-Authorization`, `WWW-Authenticate`, and `Proxy-Authenticate`. Other captures in the same scan (final 2xx/4xx, each 3xx response followed, and all surfaced 1xx responses) use this identical normalization. Names and value counts are retained. Invalid source UTF-8 in these fields is not copied into the post-redaction `header_bytes_b64` mirror; if other headers require the byte mirror, the mirror contains only the post-redaction auth placeholder.

The producer builds the same typed ordered hash projection as v14, first marshals to JSON, unmarshals to a **fresh** instance for UTF-8 normalization, marshals that projection a second time, and computes lowercase SHA-256 over the second exact byte sequence. The independent verifier replays that one final normalized serialization from received JSON. `findings`, `tool_version`, duration, timestamp, scan authorization, and redirect policy reasons remain **outside** the checksum by intentional contract design. A matching digest does not prove author, authorized scope, evidence truth, or identity. Historical v1–v14 evidence must retain its original schema identity, hash rules, and bytes.

This redaction intentionally collapses differing `nextnonce`/`rspauth`/realm/credential values to the same displayed placeholder: identical normalized hashes are *not evidence that these underlying values were equal*. Raw captures require `-include-sensitive-headers` plus a separately secured consent/evidence-storage channel. Any other response field may contain sensitive information and is **not** automatically scrubbed. Treat all artifacts as confidential unless reviewed.

## Verification

Five actual v15 Go CLI localhost fixtures have been retained in `testdata/evidence/v15_*.json`, including basic, authentication, followed redirect, 103 Early Hints and invalid-UTF8 auth values. A Python-stdlib-only verifier compares the v15 digest independently; it does not perform network IO or trust `findings`.

```sh
python3 tools/verify_evidence_v15.py testdata/evidence/v15_auth_response.json
python3 -m unittest discover -s tools -p 'test_*.py' -v
```

Standards: [RFC 7615](https://www.rfc-editor.org/rfc/rfc7615), [RFC 7616](https://www.rfc-editor.org/rfc/rfc7616), [RFC 9110](https://www.rfc-editor.org/rfc/rfc9110), [Go encoding/json](https://pkg.go.dev/encoding/json).


## v0.1.21-rc11 verifier semantic check (2026-10-15)

The standalone `tools/verify_evidence_v15.py` now rejects a v15 object that
sets `headers_redacted=true` yet retains non-placeholder values for any of the
six standard authentication fields, including 1xx and followed redirect captures.
When a `header_bytes_b64` mirror is present, those field values must contain
only base64 of the **post-redaction** placeholder. Redaction indicators must be
JSON booleans. This does not alter the v15 hash projection or historical evidence.

Previously, a maliciously assembled report could recompute a consistent hash
while contradicting the claimed redaction semantics. `verify_evidence_v13.py`
remains a **digest-only** legacy helper; consumers importing it directly for
v15 must additionally apply the v15 semantic validation function.
Neither check authenticates the author, scan scope, or truth of network data.
