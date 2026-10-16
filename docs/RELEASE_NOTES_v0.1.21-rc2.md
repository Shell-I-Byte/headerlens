> Current public release and Mac validation status: [README](../README.md) and [MACOS_QUALIFICATION.md](MACOS_QUALIFICATION.md). Historical run references in this technical document do not describe the current publication status.

# HeaderLens v0.1.21-rc2 — test-reliability fix (2026-10-09)

This release candidate is **not** a certified stable v1. The single material change is a fixed HTTP `Date` fixture in `TestRun024ConcurrentIndependentScansDeterministicEvidence`, plus the explicit positive Date-to-hash binding control `TestRun058DifferentServerDateChangesEvidenceHash`. The original concurrency test could fail if 48 concurrent responses crossed a wall-clock second. A RED reproduction logged two distinct HTTP `Date` headers. The production analyzer is unchanged except its default User-Agent build string; `headerlens.result/v15`, normalization, scope, and privacy guarantees are unchanged.

Audit inputs: Run051 sealed ZIP and complete Git bundle; original ZIP SHA-256 `be2a3d66069a1faf0998390f26ea9b29dd5aa64187da8108f85671a090830c97`. Verified Go 1.23.2/Linux locally; supported Go, Staticcheck, Govulncheck, hosted Actions and native macOS/Windows remain unverified.
