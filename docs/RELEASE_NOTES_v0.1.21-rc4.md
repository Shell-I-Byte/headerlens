> Current public release and Mac validation status: [README](../README.md) and [MACOS_QUALIFICATION.md](MACOS_QUALIFICATION.md). Historical run references in this technical document do not describe the current publication status.

# HeaderLens v0.1.21-rc4 — release candidate (2026-10-10)

## Scope
Fixes a privacy bug in the **offline, independent evidence verifier commands** only. It does not change the Go scanner, its target/redirect/scope behavior, the evidence schema (`headerlens.result/v15`), or any previously produced evidence digest.

## Reproduced problem
The Python verifier raised errors containing arbitrary JSON field names on duplicate or unsupported fields, and printed the untrusted stored digest on mismatch. This allowed malformed evidence JSON to echo synthetic secret markers in stderr/CI logs. The same three cases affected verifiers for v13, v14 and v15. Nine failures were recorded against rc3 before patching; all became passing privacy controls afterward. Historical known-good fixtures remain accepted.

## Fix
`tools/verify_evidence_v13.py` (shared by v13/v14/v15) now emits constant error wording for duplicate or unsupported keys and rejects any stored digest that is not 64 lowercase hex characters before entering the mismatch printing path. `tools/test_verifier_diagnostic_privacy.py` includes negative and correct-fixture controls for all three versions.

## Release decision
**RC ONLY.** The local Go 1.23.2 tests can be repeated, but that is not an actively supported Go release in October 2026. Supported Go 1.26.9/1.27.2, Staticcheck v0.8.1, Govulncheck v1.8.0, native Windows and macOS runtime, and actual GitHub Actions workflow runs remain unresolved. No repositories published and no remote target scanning.
