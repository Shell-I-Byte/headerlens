> Current public release and Mac validation status: [README](../README.md) and [MACOS_QUALIFICATION.md](MACOS_QUALIFICATION.md). Historical run references in this technical document do not describe the current publication status.

# Architecture

HeaderLens intentionally has a small trust surface.

```text
CLI flags
   |
   v
cmd/headerlens
   |
   v
internal/analyzer ----> net/http + crypto/tls
   |                        |
   |                        +--> one authorized HTTP(S) observation
   v
versioned Result
   |
   +--> text report
   +--> JSON report ---> future ProofGraph adapter
```

## Analyzer boundary

`internal/analyzer` owns request construction, redirect policy, bounded transport configuration, observation normalization, and deterministic rule evaluation.

Network access uses the Go standard library only. Certificate verification is never intentionally bypassed. A TLS verification error can be converted into a structured result when Go exposes the peer leaf certificate through `tls.CertificateVerificationError`; status code and HTTP version remain empty because no verified HTTP response was received.

## Observation vs. interpretation

The `Result` intentionally separates captured observations (`headers`, `tls`, redirect chain, status) from derived `findings`. The evidence digest excludes derived findings so a later rule-engine revision can reinterpret the same normalized evidence without changing its evidence identity.

The digest also excludes timing metadata, tool build version, findings, and in v12 the local redirect-block policy explanation. The blocked destination URL remains bound as normalized server-derived evidence. v4 stores the target through Go URL serialization and, when any post-redaction header value contains invalid UTF-8, includes a Base64 mirror (`header_bytes_b64`) of all captured header values. This prevents distinct HTTP `obs-text` byte sequences from collapsing to the same JSON replacement character and evidence identity. v5 strengthens the default privacy-normalized header representation. v6 additionally binds structured TLS certificate-verification success/failure state using stable categories rather than raw runtime error text. v7 privacy-normalizes server-supplied redirect URL userinfo, query payloads, and fragments before storage and hashing, while leaving the operator-supplied initial target unchanged. The digest is still not a packet capture or byte-for-byte wire transcript hash.

## Redirect model

The first URL remains authoritative for the default hostname boundary. Port safety is evaluated per hop: each upcoming redirect is compared with the immediately preceding request's effective port. Same-host redirects to a different effective port are blocked by default, except the conventional current-hop `http:80` -> `https:443` upgrade. This prevents a chain from upgrading to HTTPS and then silently moving to another service merely because that later port happens to match the initial request's port. Blocked redirects use `http.ErrUseLastResponse`, which returns the prior response without requesting the blocked destination.

Cross-host, cross-port, and downgrade relaxations are explicit CLI options. A later ScopeGuard/ProofGraph integration should enforce engagement-level authorization beyond this local hostname guardrail.

## Result schema

`headerlens.result/v15` is the current machine contract. `headerlens.result/v1` through `headerlens.result/v14` are retained as historical schemas. Backward-incompatible field meaning changes require a new schema version. Additive fields should remain optional where possible. Consumers must branch on `schema_version`, not tool build version.

## v5+ privacy boundary

The stored-header layer is intentionally not a wire transcript. In normal mode, sensitive header content is normalized before JSON storage, opaque-byte preservation, and evidence hashing. Set-Cookie retains only a security-state summary; malformed cookie fields do not retain attacker-controlled tails; Location URL userinfo/query/fragment material and Refresh navigation payloads are replaced before durable evidence is recorded. `-include-sensitive-headers` is an explicit operator opt-in for raw header evidence. ProofGraph must preserve `headers_redacted` and schema version when interpreting provenance.


## v6 TLS verification provenance

The request path never disables certificate verification. For verified HTTPS, `tls_verification.verified=true` is direct observation metadata. When Go returns a structured certificate verification failure and a peer certificate is available, HeaderLens emits `verified=false` plus a stable `error_kind`. This object is evidence-hash-bound; the detailed raw verifier message remains a derived finding and is intentionally excluded from the normalized digest.

## v7 redirect-evidence privacy boundary

URLs learned from a server redirect are evidence, but their query and fragment components are not required to prove redirect topology and commonly contain OAuth codes, signed-URL material, or other credentials. In default mode v7 replaces server-supplied userinfo/query/fragment values with deterministic redaction markers in stored Location values, redirect-chain entries, blocked redirects, and redirect-derived final URLs. The actual HTTP redirect request still uses the original URL; only the stored evidence representation is normalized. The initial target stays verbatim so operator-provided engagement input is not silently rewritten.


## v8 Refresh-evidence privacy boundary

The `Refresh` response header can direct browser navigation and can carry token-bearing URLs just like `Location`. v8 privacy-normalizes any Refresh redirect payload before JSON storage, opaque-byte mirroring, and evidence hashing. A simple delay-only value is retained; redirect-like or malformed payloads collapse to a deterministic redacted representation. `-include-sensitive-headers` remains the explicit opt-in for raw authorized evidence.

### HTTP framing provenance

Go's HTTP transport consumes some hop-by-hop framing fields during parsing. In particular, `Transfer-Encoding` can be absent from `Response.Header` while remaining visible in `Response.TransferEncoding`. Schema v9 therefore stores the parsed content length, transfer-coding list, and connection-close state as `http_framing` and binds that object into `evidence_sha256`. Protocol findings must prefer this structured parser state over pretending the cloned header map is a raw-wire transcript.

Response-status applicability is explicit: 101/204/205 do not generate missing representation-security-header findings; 304 analyzes relevant fields that are present but does not infer that absent fields were absent from the cached representation.

## v10 redirect-hop provenance

`net/http` normally returns the final response after following redirects, but intermediate 3xx responses can carry independent security state such as HSTS and Set-Cookie. HeaderLens captures each response immediately inside the redirect callback, before the transport closes it. Only hops that are actually followed enter `redirect_responses`; a blocked redirect response remains the top-level final response and is not duplicated. Server-learned hop URLs use the same privacy normalization as the redirect chain.

The hop's direct response observations are evidence-hash-bound. Nested hop findings are derived interpretation and intentionally excluded from evidence identity so a later ruleset can reinterpret the same observation without changing provenance.

Redirect following remains stateless with respect to cookies: observed Set-Cookie fields are analyzed and preserved, but no cookie jar replays them on subsequent hops. This is an explicit limitation rather than browser-emulation.

## Trailer boundary

HeaderLens does not drain arbitrary response bodies. It records parser-visible trailer field names exposed by Go before body consumption and flags analyzed security/response-control names announced for trailers. Actual trailer values that arrive only after body consumption are outside the current evidence boundary.

## v11 informational-response provenance

Go's `http.Client` returns the final response and normally does not expose non-terminal informational responses through `Response`. HeaderLens v11 attaches a request-scoped `httptrace.Got1xxResponse` observer inside the transport boundary and records each non-terminal 1xx response before it disappears. The stored observation includes the request URL plus privacy-normalized headers/opaque-byte mirror; 101 remains a terminal protocol switch and is represented by the normal final result.

RFC 8297 makes 103 Early Hints especially important to model correctly: its fields are hints and do not replace the final response's headers. HeaderLens therefore stores them as direct observations but never treats a CSP/HSTS/XFO/etc. seen only in 103 as proof that the final response has that control. Derived 1xx framing/cookie findings are excluded from `evidence_sha256`.


## v12 request-occurrence and policy/evidence separation

A URL alone is not a unique temporal request identity: redirect loops can revisit the same URL and each occurrence can receive a different set of informational responses. v12 assigns every outbound request occurrence a zero-based `request_index` at the RoundTripper boundary and stores that index on each `interim_responses` item. The index is evidence-hash-bound, so two captures with the same 1xx values and URLs but different request attachment no longer collide.

`redirect_blocked.reason` remains useful operator output, but it is a local policy conclusion (for example redirect-budget exhaustion versus cross-port refusal), not a server observation. v12 therefore hashes the normalized blocked URL but excludes the reason string. This keeps ProofGraph provenance stable if policy wording or local gate ordering changes while the observed response does not.

## v0.1.15: redacted failure diagnostics (schema stays v12)

A failed HTTP request is not a successful HeaderLens result. Go's `url.Error` string contains the attempted URL, and protocol parsing errors may quote the raw invalid field line. In default mode HeaderLens now displays only a stable, non-secret category for such failures (timeout/cancel/refused/reset/DNS/protocol); callers retain the unmodified error through `errors.Is`/`errors.As` only when they intentionally unwrap it. The explicit sensitive opt-in restores detailed human-readable failures. No HTTP observation structure or `evidence_sha256` input changed, so schema v12 is intentionally unchanged.

This does **not** establish a ProofGraph negative-evidence record. Before final/partial failures can be imported, vNext must bind completed redirect/1xx observations and a normalized failure reason to a typed outcome without conflating a failed request with an observed HTTP response. `OPEN-HL-014` tracks this work.

## v0.1.16: unsupported-scheme Location payload redaction (schema v13)

Go's `url.URL` distinguishes opaque URI syntax from hierarchical URLs, but sensitive data in a non-HTTP URI might appear in either `Opaque` or `Path` (for example `javascript:/...`). HeaderLens does not follow non-HTTP(S) redirects, so retaining their payload in default evidence offers little security-analysis value and can leak tokens. In v13 default mode, any scheme-specific Location with an unsupported scheme, or a malformed HTTP(S) scheme URL without authority, becomes `scheme:REDACTED`. When `url.Parse` fails, a valid unsupported-scheme prefix still triggers the conservative fallback. Initial operator input and normal HTTP(S) location paths remain unchanged. Tests cover 201, blocked 302, 103 Early Hints and raw-sensitive opt-in. Historical v12 hashes cannot be reused.

## v0.1.17 RC: independent replay validation and v14 UTF-8 normalization

A red-phase synthetic Go `Result` fixture demonstrated that malformed UTF-8 in producer memory may serialize differently from the consumer-side re-encoded normalized observation projection. v14 takes a fresh decode-and-reencode step before SHA-256; it does **not** rewrite historical v13 hashes. The published `tools/verify_evidence_v13.py` and `tools/verify_evidence_v14.py` independently recompute selected-observation digests from exported JSON (not digital signatures). See `docs/EVIDENCE_HASH_V14.md`, `docs/PROOFGRAPH_INGEST_V14.md` and `AUDIT_REGISTER.md`.

## v0.1.18 RC: auth-response metadata confidentiality, v15

`cloneHeader` normalizes the six standard authentication response field families to value-free placeholders **before** either UTF-8-safe display strings or an invalid-byte Base64 mirror are made. This applies to every observed HTTP response phase. Counts and presence remain observational data; values and their identity are purposefully destroyed by default. Explicit sensitive opt-in bypasses this policy. No broader claim of secret-free evidence is made for `Link`, unrecognized vendor fields or URLs with sensitive paths. This is a privacy/evidence-identity contract change, not a new network-protocol interpretation. Read `docs/EVIDENCE_HASH_V15.md` and `docs/PROOFGRAPH_INGEST_V15.md`.
