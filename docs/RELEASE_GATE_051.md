> Current public release and Mac validation status: [README](../README.md) and [MACOS_QUALIFICATION.md](MACOS_QUALIFICATION.md). Historical run references in this technical document do not describe the current publication status.

# HeaderLens v0.1.21-rc1 — local audit run 051 (2026-10-09)

**Release decision: RC only, NOT stable v1.** The evidence contract remains `headerlens.result/v15`; source change and CLI user-agent version are independent of the evidence digest scheme. No targets beyond local synthetic fixtures were contacted.

## Root-cause reproduction (BUG-HL-075)

`flag.NewFlagSet(..., flag.ContinueOnError)` with `fs.SetOutput(stderr)` reflected untrusted **unknown option names** verbatim to stderr. `-bad\nCI-SUCCESS-FAKE`, `-bad\x1b[31mUNSAFE` and Unicode bidi override appeared as raw control sequences on the original v0.1.20 compiled Linux CLI. The corrected Go tests first failed for all three cases; they now pass. A malformed flag **value** with embedded newline was already safely quoted by the Go flag parser and was not a raw control injection.

Fix: suppress raw library flag diagnostics, return constant failure text with status 2, but continue showing trusted static option descriptions. Add Go regression and compiled CLI independent probes; add smoke to CI. This does not alter scope, HTTP processing, TLS, privacy defaults or evidence schema.

## Tests and external gates

Run locally from a fresh sealed archive:

```bash
go version
go test -count=1 ./...
go test -race -count=1 -p=2 ./...
go test -shuffle=on -count=3 -p=2 ./...
go vet ./...
go build -trimpath ./...
go mod verify
python3 -m unittest discover -s tools -p 'test_*.py' -q
python3 tools/verify_evidence_v15.py testdata/evidence/v15_auth_response.json
python3 tools/verify_release_manifest.py --sealed .
go build -trimpath -buildvcs=false -o /tmp/headerlens ./cmd/headerlens
python3 tools/native_flag_security_probe.py /tmp/headerlens
```

The only locally installed Go toolchain on audit host was Go 1.23.2 (end of support); supported Go 1.26.9 and 1.27.2 were attempted with `GOPROXY=off` and failed because downloads were unavailable. Staticcheck v0.8.1 and govulncheck v1.8.0 were also attempted and blocked by missing modules. HTTPS download probe failed DNS (`curl exit 6`). GitHub project repo not found in connected list, and user has not authorized a push. **No hosted/native CI success claim.**

The source ZIP must be independently verified and rebuilt before a stable release. Source SHA-256 is an integrity reference, **not a signed attestation**.

Primary reference docs: https://pkg.go.dev/flag , https://go.dev/doc/devel/release , https://go.dev/doc/security/best-practices .
