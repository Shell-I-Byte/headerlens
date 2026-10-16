> Current public release and Mac validation status: [README](../README.md) and [MACOS_QUALIFICATION.md](MACOS_QUALIFICATION.md). Historical run references in this technical document do not describe the current publication status.

# HeaderLens v0.1.21-rc9 — 2026-10-13 (prerelease)

Release-source safety fix **BUG-HL-154-001**. The RC8 validator accepted
validly hashed source ZIP members under `.git` and `.GIT` administrative paths;
it also accepted case-folded directory prefixes (`docs/Foo/a` plus
`docs/foo/b`) and a regular file serving simultaneously as a parent directory.
Such archives may be unsafe to extract into existing Git repositories or
non-portable on Windows/macOS. RC9 rejects them before extraction.

A valid external signature/checksum is still required to authenticate an
issuer. The archive check is not proof of publisher authenticity. The runtime
analyzer, network policy and `headerlens.result/v15` evidence contract are
unchanged. Do not relabel historical RC8 artifacts.

**Unfinished v1 gates:** supported Go 1.26.9/1.27.2 runs; Staticcheck and
Govulncheck; genuine GitHub Actions results; native macOS/Windows runtime;
release publisher authorization and ProofGraph-adapter certification.
