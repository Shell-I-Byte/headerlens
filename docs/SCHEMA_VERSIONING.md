> Current public release and Mac validation status: [README](../README.md) and [MACOS_QUALIFICATION.md](MACOS_QUALIFICATION.md). Historical run references in this technical document do not describe the current publication status.

# Result schema versioning

HeaderLens treats `schema_version` as the compatibility discriminator for machine consumers such as ProofGraph. Tool release version and result schema version are intentionally separate.

## Rules

- Backward-incompatible field meaning or evidence-digest semantic changes require a new result schema version.
- Additive optional fields may stay within the current schema only when existing consumers can safely ignore them.
- Historical schema files remain in-tree so stored evidence can be validated after the CLI moves forward.
- Consumers must branch on `schema_version`, not the HeaderLens binary version.
- `evidence_sha256` is computed over the normalized observation defined by that schema version; it is not a raw packet/transcript hash.

## v1 to v2

`headerlens.result/v1` did not bind `redirect_blocked` into `evidence_sha256`. During the v0.1.2 audit this was treated as an evidence-integrity gap and v2 began hashing the blocked destination plus the then-classified reason string. v12 later refines that model by retaining the destination as evidence while reclassifying the local policy reason as derived interpretation.

`headerlens.result/v2` keeps the same JSON result shape but changes the digest profile so `redirect_blocked` is included. Because that changes the meaning of `evidence_sha256`, HeaderLens bumped the schema rather than silently changing the v1 contract.

ProofGraph adapters should support historical v1 as read-only legacy evidence and never recompute a v1 digest using v2 rules.

## v2 to v3

`headerlens.result/v2` constrained `status_code` to 0-599 and stored the caller-supplied target string verbatim. Two audit findings made that contract too narrow: Go can preserve a syntactically three-digit wire response such as 799 even though RFC 9110 declares only 100-599 valid HTTP status codes, and a raw Unicode target string can fail JSON Schema's RFC 3986 `uri` format even though Go can request the URL after serialization.

`headerlens.result/v3` therefore:

- permits `status_code` values 0-999 so the observation layer can preserve a Go-accepted three-digit wire value; HeaderLens emits `HL-HTTP-STATUS-001` when it is outside HTTP's valid 100-599 range;
- stores `target` using `url.URL.String()`, yielding URI-safe percent-encoding where needed; and
- computes `evidence_sha256` using the v3 schema identity and v3-normalized target.

These are evidence-contract changes, so they are versioned instead of being silently applied to v2. v1 and v2 remain immutable historical schemas. ProofGraph adapters reading historical evidence must branch explicitly on `schema_version`; v3 remains immutable but is no longer the preferred contract for new captures after v4.

## v3 to v4

HTTP field values can legally carry `obs-text` octets that recipients are expected to treat as opaque data. Go can retain those octets inside strings, but JSON text must be valid Unicode; `encoding/json` therefore replaces invalid UTF-8 bytes with U+FFFD. In v3, two distinct header observations such as byte `0xFE` versus `0xFF` could consequently serialize identically and receive the same normalized evidence digest.

`headerlens.result/v4` adds the optional `header_bytes_b64` observation field. It is emitted only when at least one captured post-redaction header value is invalid UTF-8; when present it mirrors every captured header value in standard Base64 so exact post-redaction bytes and array order remain available. The field is included in `evidence_sha256`. Secret-redaction policy still runs before this mirror is created, so the new field does not bypass default Set-Cookie value redaction.

Because the evidence identity changes for these observations, this is a new schema rather than a silent v3 modification. v1-v3 remain immutable historical contracts. ProofGraph adapters reading v4 must not treat `headers` alone as byte-exact evidence. New captures should use the latest schema (currently v15).

## v4 to v5

`headerlens.result/v4` preserved the post-redaction bytes of non-UTF-8 headers, but its default sensitive-header representation was still too permissive for durable evidence bundles: malformed `Set-Cookie` fields could contain secret-looking semicolon fragments, valid cookie attribute payloads such as Domain/Path/Expires were retained, and a blocked redirect could preserve URL userinfo in `Location`/redirect metadata.

`headerlens.result/v5` therefore changes the normalized observation profile in redacted mode:

- `Set-Cookie` is represented as a privacy-safe security-state summary; cookie values and attribute payloads are not retained, malformed fields collapse to a fixed redacted marker, and cookie-derived finding evidence also avoids raw Path/Domain/invalid-SameSite payloads;
- `Location` URL userinfo is redacted by default, including blocked-redirect evidence and malformed absolute/network-path Location values that `net/url` cannot parse;
- `header_bytes_b64`, when needed for opaque bytes, mirrors the **post-redaction** representation and cannot bypass the privacy boundary; and
- `evidence_sha256` binds that v5 representation.

Because these changes can alter evidence hashes even when the wire response is otherwise identical, v5 is a new immutable schema contract. ProofGraph adapters must never recompute historical v1-v4 hashes using v5 normalization rules.


## v5 to v6

`headerlens.result/v5` binds the privacy-normalized HTTP/TLS observation, but TLS certificate verification success or failure was represented only indirectly: successful connections exposed verified-chain metadata, while a verification failure primarily appeared as a derived finding. Because derived findings are deliberately excluded from `evidence_sha256`, the normalized evidence identity did not explicitly bind the certificate-verification outcome.

`headerlens.result/v6` adds optional `tls_verification` with a boolean `verified` state and, on failure, a stable categorical `error_kind`. That object is included in `evidence_sha256`. Raw Go verification error strings are deliberately not hashed because they can contain runtime-specific or time-dependent detail. Certificate-invalid reasons use named stable categories rather than Go enum integers.

This is an evidence-contract change and therefore receives a new schema version. v1-v5 remain immutable historical contracts. ProofGraph adapters should preserve the v6 `tls_verification` object as direct provenance and keep any detailed human-facing certificate error in the separate derived-finding layer.
## v7 server-redirect privacy semantics

`headerlens.result/v7` changes the normalized representation of **server-supplied** redirect URLs. In default redacted mode, URL userinfo, query payloads, and fragments learned from `Location` are replaced with deterministic `REDACTED` markers before they are stored in headers, redirect chains, blocked-redirect evidence, the redirect-derived `final_url`, and `evidence_sha256`. This protects OAuth authorization codes, state values, signed URLs, reset tokens, and similar credentials that legitimately appear in redirect URIs.

The initial operator-supplied `target` remains verbatim, including its query string, to preserve engagement input provenance; this is the documented OPEN-HL-005 boundary. `-include-sensitive-headers` preserves raw server redirect evidence when an authorized workflow explicitly requires it. v1-v6 evidence must never be reinterpreted as if it had v7 redaction semantics.

`Content-Type` remains structurally unchanged in v7, but analysis now treats duplicate field lines as ambiguous because RFC 9110 defines Content-Type as a singleton and documents security/interoperability risks when recipients resolve duplicates differently.



## v7 to v8

`headerlens.result/v7` privacy-normalized HTTP `Location` redirects, but a browser navigation URL can also arrive in the `Refresh` response header. A Refresh URL can carry OAuth-like codes, signed links, reset tokens, or fragment material and was previously retained verbatim in default durable evidence.

`headerlens.result/v8` therefore privacy-normalizes Refresh before headers are serialized, mirrored in `header_bytes_b64`, and bound into `evidence_sha256`. Delay-only values can remain visible; redirect-like or malformed payloads are replaced with deterministic redaction markers. `-include-sensitive-headers` remains an explicit opt-in for raw authorized evidence.

Because this changes the normalized observation and therefore evidence hashes, v8 is a new immutable schema. v1-v7 remain historical contracts and must not be recomputed using v8 normalization semantics.

## v9: parsed HTTP framing provenance

`headerlens.result/v9` adds optional `http_framing` to the top-level contract and requires it for observed HTTP status codes (100+). The object records Go's parsed `content_length`, `transfer_encoding`, and `connection_close` state. This is a schema bump because `Transfer-Encoding` can be consumed by `net/http` and disappear from the cloned response-header map; protocol findings based on that parser state must be cryptographically bound to direct evidence for deterministic replay and future ProofGraph adapters.

v9 does **not** reinterpret historical v1-v8 evidence. Adapters must branch on `schema_version`; an old result without `http_framing` must remain an older observation rather than being backfilled from a derived finding. The finding/applicability changes for 101/204/205/304 are derived interpretation, while the framing-state addition is the hash-bound contract change that requires v9.

## v10: followed redirect-response and trailer provenance

`headerlens.result/v10` adds `redirect_responses`, an ordered collection of responses that caused redirects HeaderLens actually followed. Each hop stores its privacy-normalized URL, status, HTTP version, headers/opaque-byte mirror, TLS state, and parsed framing state. The hop's derived findings are included for operator convenience but are deliberately excluded from `evidence_sha256`; only direct observations are hash-bound. This closes the v9 gap where HSTS, Set-Cookie, Referrer-Policy, and other headers on intermediate redirect responses disappeared once `net/http` returned the final response.

The v10 `http_framing` object also adds optional `trailer_names`, populated from parser-visible `Response.Trailer` keys without reading arbitrary response bodies. HeaderLens can therefore preserve announced trailer names and flag security/response-control fields that should not be deferred to trailers. It still does not claim a raw wire transcript: trailer values that arrive only after body consumption and raw framing fields normalized away by `net/http` remain outside the contract.

ProofGraph adapters must keep v1-v9 immutable and treat v10 redirect-hop observations as first-class temporal/provenance inputs. Nested hop findings are interpretation and must not be promoted to direct evidence.

## v11: non-terminal informational-response provenance

`headerlens.result/v11` adds `interim_responses`, an ordered list of non-terminal 1xx responses surfaced by Go's `httptrace.Got1xxResponse` callback before the final response. Each item binds the request URL plus privacy-normalized response headers and the optional opaque-byte mirror into `evidence_sha256`. Derived 1xx findings are carried for operator convenience but are intentionally excluded from the digest.

This closes a v10 provenance gap: a server could send one or more 100/102/103-style responses and those direct observations disappeared when `net/http` returned only the final response. 103 Early Hints are not interpreted as final-response security policy; RFC 8297 says their fields are hints and must not affect how the final response is processed except for speculative/performance behavior.

ProofGraph adapters must keep v1-v10 immutable. In v11, `interim_responses` should become first-class temporal observations associated with the request URL, while any nested findings remain re-derivable interpretation.


## v12: request-occurrence provenance and redirect-policy separation

Two distinct temporal captures can revisit the same URL in a redirect loop and produce the same ordered 1xx values while attaching those values to different request occurrences. v11 stored only the request URL, so those two different temporal histories could share the same normalized evidence digest. `headerlens.result/v12` adds required `request_index` to each `interim_responses` item. The initial outbound request is index 0 and every actually attempted redirect request increments the index. The index is included in `evidence_sha256`.

The v2-v11 digest profile also included the full `redirect_blocked` object, including `reason`. Audit run 015 confirmed that identical network observations could receive different digests solely because local policy configuration selected a different explanation string (for example redirect budget versus cross-port guard). v12 keeps the normalized blocked URL hash-bound but excludes the reason string as derived policy interpretation. Historical v1-v11 hashes remain immutable and must never be recomputed using v12 rules.

This split is deliberate for ProofGraph: observed destinations and temporal request attachment are provenance, while local authorization/policy conclusions belong in the re-derivable reasoning layer.

## v13: unsupported-scheme URI privacy normalization

`headerlens.result/v13` changes the default normalized evidence treatment of server-controlled `Location` URI references when their scheme is not HTTP(S), or when a scheme is present without a usable HTTP(S) authority. Previously `mailto:`, `data:`, `javascript:` and similar references could leak opaque content or path payloads into header/blocked-redirect evidence even though HeaderLens never follows them. The new default representation preserves only `scheme:REDACTED`; raw values remain accessible via explicit `-include-sensitive-headers`. The conservative fallback also handles malformed URL syntax, including invalid percent escapes on a 201 Location. Relative references and ordinary HTTP(S) paths remain visible for topology evidence and **may still contain secrets**.

Changing normalized `headers` (including 1xx, final and redirect-hop headers), `redirect_blocked.url`, or the corresponding digest requires a new evidence schema although the JSON property set is otherwise identical. Historical v1-v12 schema files and digests remain frozen; future validators must select canonicalization by `schema_version` and never silently reinterpret v12 as v13.


## Version v14 — normalized serialized-projection evidence (audit 018)

`headerlens.result/v14` retains v13's complete machine-field structure and hash field **selection**, but changes the digest *preimage* for malformed UTF-8 Go input values. Instead of directly SHA-256 hashing the first `encoding/json.Marshal` of the typed v13 observation projection, v14 marshals, unmarshals into a **fresh** copy of the projection, and marshals again. This normalizes lossy invalid UTF-8 byte escapes into valid U+FFFD Unicode before hashing; independent consumers rebuilding from the exported JSON use that same normalized representation. Both the source and stable v14 schema are versioned separately. Full operational v13 and earlier hashes and JSON schemas remain historically frozen. See `docs/EVIDENCE_HASH_V14.md` and test `TestEvidenceDigestIsRecomputableFromSerializedJSONWithInvalidUTF8`.


## Version v15 — standard authentication-response fields privacy profile (audit 019)

`headerlens.result/v15` preserves every machine property and v14's two-pass UTF-8 normalization, but changes default **value semantics** for six standard HTTP authentication fields: `Authentication-Info`, `Proxy-Authentication-Info`, `Authorization`, `Proxy-Authorization`, `WWW-Authenticate`, and `Proxy-Authenticate`. Each value is replaced with a constant marker while preserving header name and the number of field values. This is applied to final, redirect and 1xx responses before JSON and the optional byte mirror are produced. A response carrying a new server nonce can therefore intentionally share the same normalized evidence hash as the previous nonce, because the private bytes are **not retained**; changing the result schema identity is essential to avoid silently changing downstream semantics. The exact unredacted values are available only under explicit sensitive opt-in, producing a distinct hash. The v1–v14 schemas, vectors, hash rules and archived evidence remain unchanged. Clients must reject unknown schema versions rather than rehashing historical evidence with v15's redaction rules.
