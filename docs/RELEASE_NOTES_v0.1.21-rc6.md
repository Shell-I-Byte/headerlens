> Current public release and Mac validation status: [README](../README.md) and [MACOS_QUALIFICATION.md](MACOS_QUALIFICATION.md). Historical run references in this technical document do not describe the current publication status.

# HeaderLens v0.1.21-rc6

Prerelease for local testing.

## Changes

Fix missing SameSite-attribute reporting. Go leaves the parsed cookie value at
zero when the attribute is absent; the previous check only handled
`SameSiteDefaultMode`. Both forms now reach the existing attribute-presence check.

Two absence regressions failed before the fix and pass after it. Nine controls
for explicit, invalid or repeated attributes continue to pass. The missing
attribute remains a contextual INFO finding, not a confirmed vulnerability.

The observation digest and `headerlens.result/v15` schema are unchanged.

## Validation

The included acceptance suite passed all 16 scenarios on Linux AMD64. Local Go
unit, race and shuffle tests, vet, module verification and 47 Python tests passed.
The included source can reproduce the lab executable using Go 1.23.2 with
`-trimpath -buildvcs=false` and `CGO_ENABLED=0`.

The lab executable was built with an unsupported Go toolchain and is intended
only for isolated loopback testing. Supported Go builds, Staticcheck, Govulncheck
and native macOS/Windows validation are not yet confirmed. No stable-release or
production-readiness claim is made.

See [testing](https://github.com/Shell-I-Byte/headerlens/blob/v0.1.21-rc6/docs/TESTING.md)
and [security](https://github.com/Shell-I-Byte/headerlens/blob/v0.1.21-rc6/SECURITY.md).
