> Current public release and Mac validation status: [README](../README.md) and [MACOS_QUALIFICATION.md](MACOS_QUALIFICATION.md). Historical run references in this technical document do not describe the current publication status.

# HeaderLens v14 — reproducible observation digest (cross-language draft)

**Current result contract:** `headerlens.result/v14`, introduced in v0.1.17 RC. This document is a *complete version-specific amendment* to `docs/EVIDENCE_HASH_V13.md`: use the v13 document's **frozen field projection, nested types, order, omitempty semantics, Go UTF-8 JSON quoting, and SHA-256 extraction steps 1–9**, but require **v14** in step 1/2, and apply the normalization step below *before* SHA-256. The Python v14 reference script implements the resulting preimage calculation from output JSON.

## Why v14 exists: BUG-HL-071

A Go string can contain byte sequences that are not valid UTF-8. The **first** `encoding/json.Marshal` of an invalid byte emits the escaped replacement `\\ufffd`. An independent verifier sees a decoded, **valid** Unicode U+FFFD character and a subsequent Go-compatible marshal emits it as UTF-8, not `\\ufffd`. Consequently, some v13 hashes were unreproducible from the published output JSON even though no fields were tampered with. v14 fixes this lossy canonicalization boundary; it does not retroactively modify v13 hashes.

## v14 canonicalization delta (normative for this version)

1. Build the ordered typed `evidenceHash` projection *exactly* as documented for v13, except `schema_version` must be `headerlens.result/v14`.
2. Serialize projection once with Go `encoding/json.Marshal` (which deterministically transforms invalid source UTF-8 into U+FFFD escape sequences).
3. **Decode the serialized bytes into a completely fresh, zero-initialized instance of the same typed projection** — never unmarshal into shared maps/pointers of the original result. This yields only valid JSON strings; invalid original bytes are converted to U+FFFD in the decoded fields. This second-stage decoding is not needed by JSON readers consuming already-serialized v14 output, because decoding occurred at producer hashing time.
4. Marshal this normalized projection **again** with the *same ordered fields and Go JSON serialization* and SHA-256 hash the second serialization's exact bytes. Lowercase hex is `evidence_sha256`.
5. An independent consumer parses the published v14 JSON, strictly checks schema/version, constructs the exact ordered field projection, and runs the same final serializer once. Because the consumer has already decoded the normalized JSON, its SHA-256 must match the producer's step 4 digest. Consumer scripts must reject unsupported/duplicate members and preserve order of each observation array and string-array value.

This is **not RFC 8785/JCS**, not a cryptographic signature, does not protect unbound `findings`, `scanned_at`, `duration_ms`, `tool_version`, or prove scope authorization. The hash is only an integrity *checksum of selected normalized observations*, and anyone able to modify the JSON can replace the SHA-256. Signed identity, authorized scope and provenance belong in ProofGraph's future versioned, authenticated engagement bundle, separately verified from any agent/AI output.

## Independently executed evidence and fixtures

Six `testdata/evidence/v14_*.json` real locally generated Go CLI results cover normal HTTP, blocked/followed redirects, 103 Early Hints, an invalid-UTF8 response-header byte mirror, and a self-signed TLS verification failure. All recompute via the no-dependencies Python verifier. The same corpus includes the six historical `v13_*.json` fixture files, whose original hashes remain unchanged. `tools/test_verify_evidence_v14.py` and `tools/test_verify_evidence_v13.py` supply 20 independent unit/mutation checks. An additional **256 Go-generated synthetic v14 result objects**, intentionally varying malformed source bytes, Unicode, time offsets, TLS, interim/redirect data, empty values and JSON quoting, were independently checked with the Python v14 parser: **256/256 match** in the run 018 audit environment (Go 1.23.2).

```sh
python3 -m unittest discover -s tools -p 'test_*.py' -v
python3 tools/verify_evidence_v14.py testdata/evidence/v14_basic.json
python3 tools/verify_evidence_v14.py testdata/evidence/v14_certificate_failure.json
python3 tools/verify_evidence_v13.py testdata/evidence/v13_basic.json
```

Supported Go 1.26.8 and 1.27.1 (plus Staticcheck/govulncheck) remain independent release requirements until executed. Current v14 evidence represents the Go 1.23.2 test environment only; no external service, authorization, signing, or remote target was involved in these tests.

**Normative references:** [Go encoding/json](https://pkg.go.dev/encoding/json), [RFC 8785](https://www.rfc-editor.org/rfc/rfc8785), [RFC 9110](https://www.rfc-editor.org/rfc/rfc9110).
