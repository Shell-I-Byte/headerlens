> Current public release and Mac validation status: [README](../README.md) and [MACOS_QUALIFICATION.md](MACOS_QUALIFICATION.md). Historical run references in this technical document do not describe the current publication status.

# HeaderLens v0.1.19 release candidate — 2026-10-08

**Release status:** RC; still blocked on supported Go (1.26.8/1.27.1) native test matrix, Staticcheck, govulncheck, and real GitHub Actions results. No public release or native Mac/Windows execution is claimed.

**Root-cause bug fixed:** BUG-HL-073, erroneous CLI success after incomplete text, JSON, or version output. The old source reproduced the failure against synthetic failing output streams, including loopback server + CLI integration. Repaired text + JSON writers detect errors and short writes; CLI refuses success. All historical evidence schemas and digests are unchanged (`headerlens.result/v15`).

See `AUDIT_REGISTER.md`, `CHANGELOG.md`, `docs/EVIDENCE_HASH_V15.md`, `SECURITY.md` and separate Run 020 audit evidence for exact controls and limitations.
