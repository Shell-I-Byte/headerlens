> Current public release and Mac validation status: [README](../README.md) and [MACOS_QUALIFICATION.md](MACOS_QUALIFICATION.md). Historical run references in this technical document do not describe the current publication status.

# HeaderLens v0.1.21-rc10 — 2026-10-14 (prerelease)

BUG-HL-171-001: strict source ZIP preflight additionally rejects canonical-Unicode-normalized casefold aliases at file and directory-prefix levels, even when all contents have correct embedded SHA-256 manifest hashes. Three new RED controls against RC9 were confirmed; same controls pass after the patch. A positive Unicode-path control remains accepted. The original RC9 artifact is unchanged.

This is a supply-chain portability/checker fix, **not** a network scanning change. The output contract remains `headerlens.result/v15`. The embedded SHA-256 manifest does not authenticate the publisher; an out-of-band trusted release digest/signature is required. Native macOS filesystem behavior is **UNTESTED**.

Stable v1 is still **BLOCKED** by unsupported local Go 1.23.2, unavailable Go 1.26.9/1.27.2 toolchains, Staticcheck/Govulncheck, CI-run evidence, native macOS/Windows and authentic issuer provenance. Do not infer PASS from workflow configuration.
