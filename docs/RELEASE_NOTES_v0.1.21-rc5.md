> Current public release and Mac validation status: [README](../README.md) and [MACOS_QUALIFICATION.md](MACOS_QUALIFICATION.md). Historical run references in this technical document do not describe the current publication status.

# HeaderLens v0.1.21-rc5 — release candidate (2026-10-11)

## Change / root cause
Fix a **flaky offline Go regression test**, not the scanner. The previous redirect-block test compared evidence SHA-256 from two separate loopback HTTP requests to establish that a local redirect *policy reason* is excluded from the evidence hash. The synthetic server emitted an implicit current wall-clock `Date` header. If its two responses straddled a second, the correct evidence digest changed because the server-observed Date differed. Original rc4 failed under randomized shuffled tests; a 500-iteration diagnostic logged actual different Dates.

## Fix / regression
Set a fixed RFC-compliant `Date` on this synthetic response only. Add a positive control that changing the observed Date changes the evidence SHA-256. No production network/parser/hash behavior changed. Version banner, default User-Agent, CI canonical sealed-folder label and verifier CLI version assertion now consistently identify rc5.

## Release decision
**RC ONLY.** Supported Go 1.26.9/1.27.2, Staticcheck v0.8.1, Govulncheck v1.8.0, native macOS/Windows execution, authenticated publisher provenance and actual GitHub Actions run results remain unverified or blocked until independently executed. No third-party targets have been scanned. No GitHub publication without explicit consent.
