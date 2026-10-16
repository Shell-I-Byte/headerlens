> Current public release and Mac validation status: [README](../README.md) and [MACOS_QUALIFICATION.md](MACOS_QUALIFICATION.md). Historical run references in this technical document do not describe the current publication status.

# HeaderLens v13 observation hash: cross-language reproduction (draft interoperability contract)

**Scope:** `headerlens.result/v13` only. This specification describes how to reproduce HeaderLens's existing `evidence_sha256`, not how to sign or authenticate it. HeaderLens v1–v12 hashes have separate and historically frozen semantics. Do not apply this verifier to older versions or treat `v13` as RFC 8785/JCS: v13 predates a standard canonical-JSON decision.

## Threat boundary (read before using)

A matching hash only proves **internal consistency** between selected normalized fields and the recorded SHA-256 hex string. Anyone who can edit a JSON file can replace both the fields and hash. It does **not** authenticate who scanned, source trust, server identity, timestamp, target authorization, engagement scope, provenance, or safety. A matching hash **does not bind or validate** the `findings`, `tool_version`, `duration_ms`, or `scanned_at` fields, including any purported security conclusions. ProofGraph must keep those fields as unverified metadata/derived interpretation until additional signed manifest and operator verification exist. Result JSON (especially paths and custom headers) may contain secrets; treat bundles as confidential. The verifier does not execute scans or make network requests.

## Frozen v13 digest input

1. Parse the JSON as a single object, reject duplicate object-member names, and independently validate against `schema/headerlens-result-v13.schema.json` where available. Preserve integer semantics and Unicode scalar values.
2. Require `schema_version == "headerlens.result/v13"`. Build a **new projection** of the following fields in exactly this order:

   `schema_version`, `tool`, `target`, `final_url`, `status_code`, `http_version`, `headers`, `header_bytes_b64` (omit if empty), `headers_redacted`, `tls` (omit if null), `tls_verification` (omit if null), `http_framing` (omit if null), `redirect_chain` (omit if empty), `redirect_responses` (omit if empty), `interim_responses` (omit if empty), `redirect_blocked` (omit if null).

   No other top-level fields are part of the digest. This order matches the internal Go `evidenceHash` struct, **not** the published result JSON's order.
3. `redirect_responses` items project, in order: `url`, `status_code`, `http_version`, `headers`, optional nonempty `header_bytes_b64`, `headers_redacted`, optional `tls`, optional `tls_verification`, non-null `http_framing`. **Do not hash** the hop's derived `findings`.
4. `interim_responses` items project, in order: `request_index`, `url`, `status_code`, `headers`, optional nonempty `header_bytes_b64`, `headers_redacted`. **Do not hash** interim derived `findings`. Request indices and array order are significant.
5. `redirect_blocked`, when present, projects only `url` (NOT `reason`, which is local enforcement interpretation).
6. Every `headers`/`header_bytes_b64` is a JSON object mapping field names to arrays of strings, with member names sorted by Go's `encoding/json` map key ordering; each array preserves its element order. Preserve the exact post-redaction values and the byte mirror where present. Do not uppercase, URL-decode, or reclassify those values during verification.
7. `tls`, when present, projects in this order with Go's `omitempty` semantics: `version`, `cipher_suite`, `server_name`, `negotiated_protocol`, `cert_subject`, `cert_issuer`, `cert_not_before`, `cert_not_after`, `cert_dns_names`, `cert_sha256`, `verified_chains`. Empty strings/arrays/zero integer omitted except `cert_not_before` and `cert_not_after` (`time.Time` values still marshal even at zero). The two timestamps are serialized RFC3339Nano as emitted by Go, e.g. `2026-10-07T21:06:56Z`. `tls_verification`: `verified` boolean (always present), optional nonempty `error_kind`. `http_framing`: `content_length` integer, optional nonempty `transfer_encoding` array, `connection_close` boolean, optional nonempty `trailer_names` array.
8. Serialize this new projection as compact UTF-8 JSON, with Go's `encoding/json.Marshal` escaping rules for v13: struct member ordering above, maps lexicographically ordered, no unnecessary whitespace; HTML characters `&`, `<`, `>` emitted as `\\u0026`, `\\u003c`, `\\u003e`, and U+2028/U+2029 emitted as `\\u2028`/`\\u2029`. Standard JSON control-character escaping applies. Do not use a generic `sort_keys=True` serializer for the entire object or RFC 8785 JCS; that produces different bytes.
9. Compute SHA-256 of those **exact serialized bytes**, lowercase hexadecimal. Compare against `evidence_sha256`; equal means **observation digest matches**, never source authenticated.

Authoritative v13 producer implementation: `internal/analyzer/analyzer.go`, function `evidenceHash`. Python 3 stdlib-only independent implementation: `tools/verify_evidence_v13.py`. Six captured local Go CLI JSON vectors live in `testdata/evidence/`; Python unit/mutation tests: `tools/test_verify_evidence_v13.py`.

## Reproduce / verify

```sh
python3 -m unittest discover -s tools -p 'test_*.py' -v
python3 tools/verify_evidence_v13.py testdata/evidence/v13_early_hints.json
python3 tools/verify_evidence_v13.py testdata/evidence/v13_certificate_failure.json
```

A positive verification is printed as `MATCH v13 observation digest`, **not** as authenticated/signed evidence. Mutating a hashed response header, redirect, TLS certificate fingerprint, interim response index, or malformed-byte mirror must cause a mismatch. Altering only `findings`, `tool_version`, `duration_ms` or `scanned_at` still produces a matching digest **by design**; tests demonstrate this explicitly rather than implying protection that does not exist.

## Validation actually completed (audit run 018, 2026-10-07)

- On **Go 1.23.2**, generated and verified **10 distinct local/synthetic Go CLI outputs** (4 `http.server` scenarios, 5 raw HTTP wire fixtures, 1 local self-signed TLS certificate verification failure). These cover followed/blocked redirects, default redaction, 103 Early Hints, malformed/opaque Location, invalid UTF-8 bytes with base64 mirrors, nonstandard 599, HTML-escaped field bytes and certificate failure.
- All 6 frozen JSON vectors independently pass Python digest checks and local JSON Schema Draft 2020-12 validation (external `jsonschema` package installed in audit runtime, *not* required by verifier). 10 stdlib Python regression tests pass, including mutations and excluded-field negative controls.
- Supported Go **1.26.8/1.27.1** and external staticcheck/govulncheck gates remain **unverified locally**. The verifier has not been independently cross-tested against their JSON encoding behavior. This is a draft interoperability bridge, **not** a promise of a globally stable universal canonicalization protocol.

## Planned evolution for ProofGraph

Design a new, versioned signed engagement bundle with independently specified canonicalization (consider RFC 8785 as an evaluated option), object-level content identifiers, an explicit hash domain separator, hash algorithm agility, trusted signing key/discovery, authorization scope manifest, evidence freshness, actor/tool identity, signed observations distinct from interpretations, temporal revalidation/replay, and deterministic failure/incomplete-observation states. Do **not** silently reinterpret historical HeaderLens v13 hashes as new ProofGraph signatures.

Primary normative references: [Go encoding/json](https://pkg.go.dev/encoding/json), [RFC 8785](https://www.rfc-editor.org/rfc/rfc8785), [Go release history](https://go.dev/doc/devel/release), [RFC 9110](https://www.rfc-editor.org/rfc/rfc9110).


## Historical limitation discovered in audit run 018

**BUG-HL-071 (fixed for new output in v14, not retroactively in v13):** v13 hashing can become impossible to reproduce from exported JSON if a non-header hash-bound Go string contains malformed UTF-8 bytes before initial JSON serialization. Go's first encoder writes `\ufffd` for an invalid byte sequence, whereas a consumer re-encoding decoded U+FFFD writes the literal valid codepoint. The v13 CLI verifier therefore cannot prove all conceivable v13 results; a mismatch may indicate this lossy boundary rather than a malicious alteration. **Never silently reassign a different hash to historical v13 evidence.** For new results, emit v14 and use the v14 verifier; it normalizes before hashing and passed 256 deliberately varied local synthetic cross-language probes including malformed bytes.
