# HeaderLens

I’m publishing HeaderLens as a focused HTTP security-header inspection tool. It collects structured observations, handles redirect scope explicitly, and keeps evidence verification separate from interpretation.

Inspect HTTP security headers and produce structured, reproducible evidence.

## Get started

Download the **macOS ARM64** archive from [Releases](https://github.com/Shell-I-Byte/headerlens/releases), or build from source with a supported Go toolchain. This release was tested with **Go 1.27.2 and Go 1.26.9** on native Apple Silicon macOS. I recommend Go 1.27.2.

```sh
git clone https://github.com/Shell-I-Byte/headerlens.git
cd headerlens
go build -trimpath -buildvcs=false -o headerlens ./cmd/headerlens
```

Try the included example:

```sh
./headerlens -json https://example.com
```

This network example is illustrative; use a target you own or are explicitly authorized to assess. Public examples were validated against local fixtures, not example.com.

## What I’m shipping

- Source, tests, schemas, technical documentation, and synthetic examples.
- A locally built and tested macOS ARM64 binary, with SHA-256 checksums.
- Strict input handling and explicit limits rather than an automatic vulnerability verdict.

This is **v0.1.21-rc11**, a release candidate. The [qualification record](docs/MACOS_QUALIFICATION.md) explains exactly what was tested and how the public source snapshot relates to the local qualification. Public binaries are rebuilt from this repository’s canonical Go module path and tested again before release.

## Validation

```sh
go test -count=1 ./...
go test -race -count=1 ./...
go test -shuffle=on -count=2 ./...
go vet ./...
go mod verify
go run honnef.co/go/tools/cmd/staticcheck@v0.8.2 ./...
go run golang.org/x/vuln/cmd/govulncheck@v1.9.0 ./...
```

The native Mac checks pass, including positive and negative CLI cases. Historical local results are not GitHub Actions results. Workflow configuration is included; hosted Actions is disabled for this initial publication. No Linux or Windows native release is claimed here.

## Boundaries

Only inspect targets you own or have explicit permission to assess. A missing header is an observation, not proof of an exploitable vulnerability.

Use physical directory paths for hardened Mac file operations: symlinked parents are rejected. The protection covers the tested symlink substitutions; it is not a filesystem snapshot and does not defend against privileged mount changes or a compromised user account. Mac binaries are ad-hoc linker-signed, **not Developer ID signed or notarized**. Do not disable operating-system protections to run them.

Please read [SECURITY.md](SECURITY.md) and the technical documentation in `docs/` before using real data. The bundled dependency notices and existing copyright notices are retained.

## License

MIT. See [LICENSE](LICENSE).
