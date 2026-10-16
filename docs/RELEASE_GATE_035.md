> Current public release and Mac validation status: [README](../README.md) and [MACOS_QUALIFICATION.md](MACOS_QUALIFICATION.md). Historical run references in this technical document do not describe the current publication status.

# HeaderLens release gate audit 035 (2026-10-08)

**Status:** v0.1.20 RC, `headerlens.result/v15`, no change to product runtime or evidence schema. Do not call this stable v1.

## Confirmed local CI failure

The previous workflow executes `go build -trimpath ./cmd/headerlens` before Python manifest unit tests. Go creates an untracked `./headerlens` executable. The manifest unit test then correctly rejects the generated file: `unlisted source: headerlens`, so the original workflow would fail on its Linux test jobs even if current Go and analyzers were available. This was reproduced against source from run 034: pre-build unittest 32/32 PASS, build exit 0, post-build unittest exit 1 (one failure), direct verifier exit 1.

**Correction:** build all Go packages with `go build -trimpath ./...` without polluting the working tree; immediately verify the clean source manifest. The original seven checks remain present. Python evidence-verifier tests continue to execute. The native smoke job also uses `go build ./...`.

## Native release gating

`native_smoke` now runs automatically on v1.* tag pushes as well as manual dispatch; it uses `macos-15` ARM64 and `windows-2025` AMD64, explicitly asserts `go env GOOS/GOARCH`, and runs native Go tests, vet, build, and CLI `-version`. Private repo hosted minutes may be billable. **No hosted CI has executed** (no authorized HeaderLens GitHub repository). This config does not independently prove a native runtime pass or block GitHub Release publishing by itself; humans must verify job results before calling a release stable.

## External prerequisites

- Supported Go 1.26.8/1.27.1 tests, Staticcheck v0.8.1 and govulncheck v1.8.0 remain absent locally; `proxy.golang.org` DNS failure previously reproduced and is retried in this round.
- A real private repository and actual Actions workflow/job artifacts require explicit consent before any write.
- No external targets scanned. All tests remain local/synthetic; cross-compiles are NOT native runtime evidence.
- Historically reported fixed-root-cause counts have not all been independently revalidated this round.

Sources: official Go release policy `https://go.dev/doc/devel/release`, GitHub-hosted runner labels `https://docs.github.com/en/actions/reference/runners/github-hosted-runners`, and upstream tagged analyzer refs `dominikh/go-tools v0.8.1`, `golang/vuln v1.8.0` (verified read-only through GitHub API). Local CI simulation is not a substitute for real GitHub Actions.

## Reproducible binary identity

An independent falsification compared binaries built from the Git commit and the byte-identical sealed ZIP using only `-trimpath`. **Hashes differed**: the Git builds embed `vcs=git`, `vcs.revision`, and `vcs.time` in Go build information while the ZIP has no `.git`. Local `go version -m` confirmed the precise cause. This is not a source tamper.

**Canonical cross-source release binary command** (one Go version and identical GOOS/GOARCH/CGO env):

```bash
go build -trimpath -buildvcs=false -o /tmp/headerlens ./cmd/headerlens
```

Set `-buildvcs=false` in the hosted binary-smoke command as well. Preserve Git SHA and source ZIP digest in external release metadata. Required confirmation: three compiled binaries from committed working tree, sealed ZIP and fresh Git-bundle clone must be **byte-identical**. Cross-compilation still does not prove native macOS/Windows functionality.

A synthetic query-token probe initially failed the test harness because it incorrectly expected operator-supplied query strings to be scrubbed; `README.md` lines on the v7+ contract explicitly retain operator input verbatim, while server-supplied redirect payloads are redacted by default. Correct the harness and preserve this known limitation.
