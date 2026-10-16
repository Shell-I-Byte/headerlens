> Current public release and Mac validation status: [README](../README.md) and [MACOS_QUALIFICATION.md](MACOS_QUALIFICATION.md). Historical run references in this technical document do not describe the current publication status.

# HeaderLens v0.1.21-rc1 — release candidate (2026-10-09)

- Fixed `BUG-HL-075`: attacker-provided invalid CLI flag names could inject ANSI escape, newline or Unicode bidi-control sequences into logs. Changed diagnostics to constant text without reflecting arguments; retained static usage/help.
- Added four CLI error-path test vectors with explicit positive `-version` smoke. Native smoke is invoked by CI after building the real binary.
- No changes to `headerlens.result/v15`, evidence SHA-256 projection, HTTP request policy or TLS verification behavior.
- **Not stable v1**: current supported Go runtimes, Staticcheck, govulncheck, GitHub Actions and native macOS/Windows executions remain BLOCKED/UNTESTED. See `docs/RELEASE_GATE_051.md`.
