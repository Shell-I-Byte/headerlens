> Current public release and Mac validation status: [README](../README.md) and [MACOS_QUALIFICATION.md](MACOS_QUALIFICATION.md). Historical run references in this technical document do not describe the current publication status.

# Release gate / audit round 024 (2026-10-08T06:09:39+02:00)

Source candidate: HeaderLens v0.1.20 RC, contract `headerlens.result/v15`. This pass adds **tests and native CI architecture checks only**. There is no application source change, no new verified product root cause and no version bump. The historical register reports 73 fixed root causes (BUG-HL-050 retired), not individually re-proven in round 024.

## New coverage

- `TestRun024AlreadyCancelledNeverSendsRequest`: cancellation before invocation produces `context.Canceled` without contacting loopback test server.
- `TestRun024ConcurrentIndependentScansDeterministicEvidence`: 48 parallel local-only `Analyze` calls produce identical normalized SHA-256 observations.
- `TestRun024IPv6LoopbackNoExternalTraffic`: actual IPv6 loopback GET with correct source and final URL; test `Skip` only if IPv6 unavailable.
- Native CI `GOOS`/`GOARCH` identity step must fail closed on runner mismatch; localhost YAML parser PASS, hosted job UNTESTED.

## Hard release blockers

Go 1.23.2 is end-of-support. GitHub Actions matrix targets Go 1.26.8/1.27.1, Staticcheck v0.8.1, govulncheck v1.8.0 and native macOS ARM64/Windows AMD64, but none have been executed on their intended platforms. The GitHub connector returns 404 for `077-Protocol/headerlens`; the user's seven accessible repositories do not include it. Never claim that a workflow specification proves its execution. The source ZIP has not been published.

## Release finishing procedure

After obtaining explicit authorization and a suitable repository, upload **these exact audited source bytes** and run the existing CI workflow including `workflow_dispatch` (for native smoke). Inspect required job conclusions, platform checks and analyzer release tests, then bind results to commit SHA + source ZIP digest. Resolve any findings, reseal ZIP, and repeat from sealed source. Only then consider the stable v1 gate.

Primary verification references: https://go.dev/doc/devel/release ; https://github.com/actions/runner-images ; https://docs.github.com/en/actions/reference/runners/github-hosted-runners .
