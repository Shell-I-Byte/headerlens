> Current public release and Mac validation status: [README](../README.md) and [MACOS_QUALIFICATION.md](MACOS_QUALIFICATION.md). Historical run references in this technical document do not describe the current publication status.

# HeaderLens v0.1.20 RC — CI native gate integrated (2026-10-08T05:07:45+02:00)

This is a **CI-only candidate refresh**, not a product code change or a stable v1 declaration. Source parent archive SHA-256: `a149fca13c34d9004f633318b731334f7b40dda9d3c0e6e8bf2ebc31415fd243`. Same `headerlens.result/v15` evidence contract and application code.

`.github/workflows/ci.yml` now includes `workflow_dispatch` and opt-in `native_smoke` jobs using `macos-15` (ARM64) and `windows-2025` (AMD64). Existing Ubuntu test/quality jobs still target exact Go 1.26.8 and 1.27.1, Staticcheck v0.8.1 and govulncheck v1.8.0. No hosted CI job has run and no native binary has been executed in this audit. The local PyYAML parse does not replace actionlint/GitHub Actions schema validation.

Run023 corrects a prior **audit manifest** packaging problem (Run022 missing standalone coverage ledger) in the separately sealed Run023 release bundle. The problem is NOT a HeaderLens product defect.

Required next action: with explicit repository publishing permission, create/populate dedicated repository (or supply approved destination), run hosted Ubuntu+quality checks and manual native smoke; retain real URLs/logs bound to final source SHA. Never present this source as stable until all gates are satisfied.
