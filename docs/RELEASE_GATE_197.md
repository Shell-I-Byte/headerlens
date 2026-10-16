> Current public release and Mac validation status: [README](../README.md) and [MACOS_QUALIFICATION.md](MACOS_QUALIFICATION.md). Historical run references in this technical document do not describe the current publication status.

# HeaderLens release-gate audit 197 — 15 October 2026

Status: **CI GATE CONFIGURATION IMPROVED**, not a stable release. Current CLI `0.1.21-rc11`; `headerlens.result/v15` unchanged.

## Confirmed failing release configuration

The previous `native_smoke` job used a job-level `if:` that skipped native platform checks for ordinary branch pushes and pull requests. It only ran after an explicit manual dispatch or a v1.* tag. Also, its final runtime action was only `go run ./cmd/headerlens -version`: no negative actual compiled binary exit-code or diagnostic controls.

### Executed red/green control

- Added `tools/test_native_pre_release_gate.py` and updated `tools/test_release_ci_contract.py` with stronger requirements.
- On the original unmodified CI YAML, 2 of the three independent new tests **FAILED** (required native execution before tagging and real compiled positive/negative CLI execution); one pre-existing architecture condition **PASSED**.
- Removed the tag/manual-only job condition. The native job now runs for push, PR and manual dispatch, including a v1.* tag.
- Build the real program using `go build -trimpath -buildvcs=false`, then run `tools/native_flag_security_probe.py` on the compiled binary on each native matrix job. No HTTP network targets are used by the flag probe. Unsupported missing Python runtime is an explicit failed job.
- All 3 new tests and the modified 5 CI-contract tests passed locally after this change. PyYAML parsing locally found `test`, `quality`, `native_smoke` jobs; native job has no `if`.

## What is still not evidence

- **UNTESTED**: Hosted GitHub Actions outcomes; native Linux ARM64, macOS ARM64, Windows AMD64 runs. Runner availability and SHA-pinned action lines alone are not runtime results.
- **BLOCKED**: Go 1.26.9 or 1.27.2, Staticcheck v0.8.1, Govulncheck v1.9.0 (not present locally, toolchain download DNS unresolved).
- **OPEN**: signed release provenance, actual v15 ProofGraph adapter qualification, publishing/module identity review. Do not publish without explicit permission.
- No material product defect was detected in this focused CI review; no new RC version was issued.

## Trust boundaries

Synthetic local loopback acceptance is a test, not authority to scan third-party endpoints. `headerlens.result/v15` SHA-256 is an integrity digest, NOT a signed publisher attestation; AI analysis cannot promote unsupported findings to confirmed observations or override scope.
