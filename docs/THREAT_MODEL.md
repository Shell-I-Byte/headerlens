> Current public release and Mac validation status: [README](../README.md) and [MACOS_QUALIFICATION.md](MACOS_QUALIFICATION.md). Historical run references in this technical document do not describe the current publication status.

# Threat model

## Assets to protect

1. operator/client secrets present in response metadata
2. engagement scope and authorization boundaries
3. integrity of captured evidence
4. operator workstation availability
5. correctness of findings presented to a pentester

## Untrusted inputs

Everything returned by the target is untrusted, including redirect locations, headers, cookie syntax, certificates, status codes, protocol negotiation, and deliberately contradictory fields.

Environment proxy variables are also treated as untrusted for evidence collection and are disabled by default.

## Primary threats and controls

| Threat | Control |
|---|---|
| redirect causes an unintended request to another hostname | cross-host redirects blocked by default |
| same-host redirect crosses into a different service port, including later hops after an allowed upgrade | compare every redirect with the immediately preceding request effective port; only the conventional current-hop `http:80` -> `https:443` upgrade is implicit; explicit opt-in required otherwise |
| HTTPS response redirects to plaintext HTTP | downgrade blocked by default |
| redirect loop | explicit redirect budget |
| slow/hostile endpoint stalls the CLI | overall + transport timeouts |
| oversized response headers consume excessive memory | `MaxResponseHeaderBytes` bound |
| TLS interception/invalid certificate is silently trusted or loses provenance | normal x509 verification; no insecure fallback; v6 hash-binds stable verification success/failure state |
| cookies leak into evidence or prefix rules are bypassed by parser normalization | Set-Cookie value redaction by default; malformed-cookie findings retain only redacted values/counts; prefix validation checks raw Domain-attribute presence, including `Domain=` |
| operator target embeds username/password or misleading client-only fragment evidence | target URL userinfo and fragments rejected |
| environment proxy changes the observed path | proxy environment ignored by default |
| duplicate/contradictory security headers create false confidence | dedicated duplicate handling for critical implemented checks; cookie duplicate parsing uses HTTP OWS only; CSP first-directive semantics and comma-delimited policy lists are preserved for `frame-ancestors` |
| non-ASCII whitespace is silently normalized into valid security-header syntax | protocol-specific ASCII OWS / CSP ASCII-whitespace parsing is used for security decisions rather than generic Unicode trimming |
| syntactically three-digit but HTTP-invalid status values disappear or violate the machine schema | preserve the observed integer in v3 and emit `HL-HTTP-STATUS-001` outside 100-599 |
| raw Unicode target input violates the published URI-format schema | store/hash the request target using `url.URL.String()` serialization |
| opaque HTTP `obs-text` bytes are collapsed by JSON UTF-8 replacement, allowing distinct observations to share an evidence digest | v4 emits a Base64 mirror of post-redaction header bytes whenever invalid UTF-8 is observed and binds it into `evidence_sha256` |
| tool interpretation changes evidence identity | digest excludes derived findings and, in v12, the local blocked-redirect policy reason; only the normalized blocked URL remains evidence-bound |
| untrusted header/URL text spoofs the operator terminal with control or bidirectional formatting | human-readable output visibly escapes terminal control and Unicode bidi-control characters; JSON keeps a valid-UTF-8 display value and v4 adds a byte-preserving Base64 mirror when opaque non-UTF-8 header bytes are present |
| server redirects place OAuth codes, signed-URL secrets, or state in evidence URLs | v7 privacy-normalizes userinfo/query/fragment material learned from server redirects before storage/hash; raw capture requires explicit sensitive opt-in |
| unsupported-scheme Location (data/mailto/javascript) carries sensitive URI payload into evidence | v13 conservatively redacts unsupported or malformed scheme-specific URI content, including opaque/path payloads, preserving only the scheme by default |
| Refresh header carries a signed URL/token into durable evidence | v8 retains only safe delay state and replaces the navigation payload before storage/hash unless sensitive capture is explicitly enabled |
| ambiguous duplicate Content-Type changes response-context classification across recipients | emit a protocol warning and avoid JSON/API-specific downgrade unless exactly one Content-Type field is present |
| AI/downstream system invents provenance | versioned machine contract + evidence digest; v6 makes TLS verification status a direct observation rather than requiring inference from findings |
| non-terminal 1xx responses disappear or become ambiguously attached when redirect loops revisit the same URL | v12 retains v11 `Got1xxResponse` capture and hash-binds a zero-based request occurrence index; 103 Early Hints are never promoted to final-response policy |
| 205 Reset Content advertises positive response content without a protocol signal | parser-visible positive Content-Length on 205 is flagged; body bytes are still not drained merely to prove a zero/nonzero chunked body |

## Accepted/residual risks

- DNS resolution can change between operator authorization and request execution
- redirects on explicitly permitted cross-host mode can leave the original scope if the operator misconfigures authorization
- only response headers and connection metadata are analyzed; application behavior is not proven safe
- CSP and Permissions-Policy parsing are deliberately incomplete
- the normalized evidence digest is not cryptographic proof of server authorship and does not replace signed evidence, a packet capture, or a tamper-evident engagement vault


## v15 authentication-response confidentiality boundary

RFC 7615/7616 authentication response fields may include nextnonce, rspauth, challenge or other scheme-specific authentication parameters. The default evidence pipeline collapses six standard authentication field values to a constant marker, preserving presence/count only. No ordinary findings depend on the omitted values. This prevents common auth metadata from accidentally appearing in portable default evidence, at the cost of losing nonce-specific or authentication-scheme forensic fidelity. Explicit opt-in can restore original values but requires an authorized, confidential handling channel. **No blanket scrubbing guarantee:** custom authentication headers, Link, path segments, caller-supplied URL parameters, and TLS certificate metadata remain potentially confidential.
