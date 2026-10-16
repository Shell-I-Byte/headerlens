> Current public release and Mac validation status: [README](../README.md) and [MACOS_QUALIFICATION.md](MACOS_QUALIFICATION.md). Historical run references in this technical document do not describe the current publication status.

# ProofGraph ingest draft: HeaderLens v14

**Status:** DESIGN/UNIMPLEMENTED ProofGraph adapter. The normalized v14 digest has been independently validated locally; no ProofGraph binary is claimed to exist.

- Accept only an explicitly supported `schema_version` (`headerlens.result/v14` for new evidence; archived v13 with legacy decoder rules), and validate the matching JSON Schema before ingest. Unknown future versions fail closed until a migration exists. Migrations **must never silently rehash** historical v13 bundles as if they were v14 source observations.
- Verify the **normalized observation subset** using the appropriate independent v14 digest verifier and `docs/EVIDENCE_HASH_V14.md`. Treat SHA-256 match as self-consistency only; a signed engagement manifest from a separately verified actor/authorization/scope context is required to label any source authenticated.
- Map `target`, `final_url`, `status_code`, `http_version`, raw-redacted `headers`, byte-mirror `header_bytes_b64`, `http_framing`, `tls`, `tls_verification`, `redirect_chain`, `redirect_responses`, `interim_responses` and `redirect_blocked.url` to typed, immutable **observed** nodes/edges with per-request index and provenance. Any `redirect_blocked.reason` is **local policy inference**, not a remote network fact.
- Findings, header risk scores, missing security headers, certificate severity, and any attack-path implications are separate **inferred/hypothesis** graph entities, never automatically confirmed. Mark TLS verification failures explicitly without interpreting a missing HTTP response as negative proof of security controls.
- No auto-expansion of authorization to other hosts/ports, no autonomous exploit/scanning actions from evidence alone, and no automatic confidence elevation by AI. AI can suggest analysis but may not synthesize provenance, scope, certainty, or human approval.
- Track observation freshness/uncertainty, versioned adapter identity, contradicting observations, independent agreement versus duplicated data sources, and stable deterministic replay fixtures. Signed source identity, schema migration, temporal sequence integrity, negative evidence, and partial failure-outcome manifests remain ProofGraph's future design work.
- Treat all result JSON as possibly containing secrets in URL paths, `Link`, custom headers, and caller-provided URLs even when `headers_redacted` is true. Restrict portable engagement bundle sharing accordingly.

This draft extends the v13 ingest handoff without pretending that a README is a working ProofGraph implementation.
