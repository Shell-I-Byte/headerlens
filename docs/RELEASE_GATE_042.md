> Current public release and Mac validation status: [README](../README.md) and [MACOS_QUALIFICATION.md](MACOS_QUALIFICATION.md). Historical run references in this technical document do not describe the current publication status.

# Run 042 — CI release qualification, not a stable release

Date: 2026-10-09 Europe/Amsterdam. HeaderLens remains **v0.1.20 RC**, JSON contract `headerlens.result/v15` unchanged.

## Why the change

Go upstream published Go **1.26.9** and **1.27.2** security updates on **2026-10-08**. The existing workflow still installed older patch releases 1.26.8 and 1.27.1. This is a release gate deficiency, **not a confirmed runtime exploit**.

Upstream: https://go.dev/doc/devel/release#go1.27.2 and https://go.dev/doc/devel/release#go1.26.9.

## CI expectations

The pinned CI must run the updated 1.26.9/1.27.2 matrix, staticcheck@v0.8.1 and govulncheck@v1.8.0, independent evidence vectors, exact source manifest, and native macOS ARM64 / Windows AMD64 jobs before v1 release approval. The `v1.*` tag now explicitly triggers the native job, and workflow dispatch can exercise it before the tag. Native goos/goarch are checked. The workflow uses full commit SHAs for GitHub actions.

## Local validation

To recheck configuration (not a hosted CI claim): `python3 -m unittest tools.test_release_ci_contract -v`. Then `go test -count=1 ./...`, `go test -race -count=1 ./...`, `go test -shuffle=on -count=3 ./...`, `go vet ./...`, `go build -trimpath -buildvcs=false ./...`, `go mod verify`.

To verify final source archive: `python3 tools/verify_release_manifest.py --sealed EXTRACTED_SOURCE_ROOT` before running code; then rerun suites from extracted ZIP.

Supported toolchains, analyzers and actual macOS/Windows test runs are not available in the current isolated runner; **release status remains BLOCKED**. No GitHub source publication is authorized or performed.
