> Current public release and Mac validation status: [README](../README.md) and [MACOS_QUALIFICATION.md](MACOS_QUALIFICATION.md). Historical run references in this technical document do not describe the current publication status.

# ProofGraph input contract — HeaderLens v12 (draft integration handoff)

**Status:** integration draft for a future, independent ProofGraph repository, not a claim that ProofGraph itself is built. The public machine result is `headerlens.result/v12`; the authoritative schema is `schema/headerlens-result-v12.schema.json`. Historical v1–v11 contracts must not be reinterpreted as v12.

## Trust boundaries

1. `target` is an **operator-provided** URL, not proof that the target is authorized. Engagement scope must be independently checked by ScopeGuard/ProofGraph. Source URLs and timestamps can contain sensitive metadata.
2. `headers`, `header_bytes_b64`, `tls`, `tls_verification`, `http_framing`, `redirect_responses`, and `interim_responses` are **normalized direct observations** at the Go HTTP parser boundary. They are not raw wire transcripts or independently authenticated server statements.
3. `findings`, `redirect_responses[].findings`, `interim_responses[].findings`, and `redirect_blocked.reason` are **derived** interpretations/policy actions, not independently observed exploit facts. They do **not** contribute to the v12 evidence digest. `redirect_blocked.url` does.
4. `evidence_sha256` is a deterministic hash of selected normalized observations. It is **not** an HMAC, signature, proof of possession, trust attestation, scan authorization, nor a guarantee the source data was not constructed locally. ProofGraph engagement bundles must add independent provenance (engagement scope and signer identity) instead of treating hash equality as authenticity.
5. `scanned_at` and `duration_ms` are excluded from the digest. They can inform temporal freshness, but replay integrity of time requires an independent signed manifest. Equal digests need not represent the same request occurrence or engagement.

## Suggested adapter mapping

| HeaderLens field | Proposed Security IR interpretation | Confidence gate |
|---|---|---|
| `target`, `final_url`, `redirect_chain` | Target identifiers + observed redirect relationships; keep source URL distinct from server-derived URLs | `observed` for received redirect evidence only; initial target remains asserted/operator-supplied |
| `redirect_responses[i]` | Ordered HTTP observation for the response preceding followed redirect `i` | `observed`; preserve order and do not infer endpoint exploitability |
| `interim_responses[].request_index` | Zero-based outbound RoundTrip occurrence for that interim response | `observed` attachment to its request occurrence, not to URL identity alone |
| `tls_verification` | TLS verification result and categorical failure state | `observed` for this client/connection; not global certificate health |
| `http_framing` | Go parser-visible framing and trailer-name observations | `observed` parser state, not raw request-smuggling evidence |
| `findings` | Candidate policy/rule interpretations with linked evidence refs | `inferred` by default, never `confirmed exploitation` without separate validation |
| `redirect_blocked.reason` | Scope-policy decision | Local authorization decision, not server-observed evidence |

## Replay & negative-evidence constraints

- Validate exact `schema_version` against its frozen JSON Schema; retain the original JSON byte payload, tool release, chosen normalization mode and source artifact digest in an engagement bundle.
- Avoid cross-version automatic digest rewrites. Reclassification can produce a new *derived* finding set over the same input without changing the underlying v12 digest.
- Because the digest is currently generated with a Go-specific internal JSON structure (`encoding/json` field order/escaping), an independently published canonicalization test-vector suite and verifier are still required before other-language tools can cryptographically verify `evidence_sha256` from arbitrary result JSON. **Do not assert verification from schema-validation alone.**
- A failed connection currently returns a sanitized error, not a machine-verifiable result containing previous partial observations (`OPEN-HL-014`). No HTTP status / negative result must be invented from stderr.
- Stable finding IDs are *rule-instance labels*, not unique IDs. Cookie findings can collide. Store unique node identity separately.
- AI may summarize observations but must not assert missing data, upgrade evidence states, authorize targets, or create observations. Contradictions and unresolved hypotheses must remain explicit.

## Source compatibility

This draft is specific to `headerlens.result/v12`. Future ProofGraph IR revisions must version typed nodes, typed edges, evidence normalization, timestamps, trust assertions, and migration behavior independently of HeaderLens release numbers. Nmap/Nuclei/Burp/cloud adapters should not impersonate HeaderLens evidence or reuse its digest canonicalization without source-specific contracts.

## Local v12 golden digest vector

`internal/analyzer/TestEvidenceHashV12GoldenVector` fixes one deliberately synthetic v12 observation containing final response data, a redirect, an informational response with `request_index=1`, sorted header-map keys, HTML-sensitive characters in header values, and excluded derived findings. On the available Go 1.23.2 runtime, the expected normalized digest is:

`711bd9b58fb8b061be195e852cd3a6be2440b89e2d499cd74080f2d747fc4436`

The test also mutates tool version, elapsed duration, and nested derived findings without changing the expected digest. This is **one Go-internal conformance vector**, not yet an independent language-neutral canonicalization specification. Go 1.27 changed JSON internals; the supported-toolchain CI gate must run this vector and a broader suite before a stable release is claimed.
