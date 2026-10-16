> Current public release and Mac validation status: [README](../README.md) and [MACOS_QUALIFICATION.md](MACOS_QUALIFICATION.md). Historical run references in this technical document do not describe the current publication status.

# HeaderLens v0.1.21-rc3 — release candidate (2026-10-09)

No observation or schema changes: `headerlens.result/v15` is preserved.

BUG-HL-059-001: help requests (`-h`, `-help`, `--help`) previously returned error exit status 2 and emitted an invalid-option diagnostic after valid help text. These now exit 0 with trusted usage only. Invalid/malformed options continue returning 2, and help output does not print user-supplied flag content. New RED/GREEN Go regressions and real compiled CLI probes.

Release is **not** stable v1: current Go 1.26.9/1.27.2, Staticcheck v0.8.1, Govulncheck v1.8.0, GitHub Actions and native macOS/Windows execution need independent PASS. No GitHub publication without explicit permission.
