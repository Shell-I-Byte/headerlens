> Current public release and Mac validation status: [README](../README.md) and [MACOS_QUALIFICATION.md](MACOS_QUALIFICATION.md). Historical run references in this technical document do not describe the current publication status.

# HeaderLens v0.1.21-rc11 — 2026-10-15 (prerelease)

**Security-consistency fix:** independent v15 verification now rejects forged or malformed evidence objects whose claimed default auth-field redaction is contradicted by raw authentication values or opaque-byte mirrors. The prior v15 digest-only verifier would print `MATCH` if an attacker recomputed the report checksum. Nested 1xx and 3xx evidence is covered; raw capture opt-in remains supported. Wire schema and hash projection remain `headerlens.result/v15`.

This check is a **semantic validity check**, not a signature, scope attestation, or proof the producer observed the claimed response. Go 1.23.2 lab-only; supported-toolchain, Staticcheck/Govulncheck, native macOS/Windows/ARM64, GitHub Actions execution, signed publisher provenance, and ProofGraph adapter release qualification remain **BLOCKED/UNTESTED**.
