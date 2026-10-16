# Native macOS qualification

## Release scope

HeaderLens is published as `github.com/Shell-I-Byte/headerlens`, version **v0.1.21-rc11**. This is a clean public snapshot derived from locally qualified source commit `028ddff1e2c4aac6956ee17a509c0418ae78f90e`. Private development history, personal workstation paths, and raw local logs are excluded.

The original source was executed natively on Apple Silicon macOS 15.7.4 with Go 1.27.2 and 1.26.9, CGO enabled, and Apple clang 17.0.0. Unit, race, shuffled, vet, build, module, Staticcheck 2026.2.2 (v0.8.2), Govulncheck v1.9.0, and positive/negative CLI checks passed. Known deliberate fuzz-seed skips are not counted as passed test cases.

Before publication, this repository's canonical module path is rebuilt and validated again locally. Release assets include a machine-readable qualification record tied to the exact public commit and binary checksums. The release is published only after those checks pass. A workflow file is not evidence of a completed GitHub Actions run.

## Darwin filesystem behavior

The relevant report writers pin output-directory descriptors and reject symlinks in ancestor components. JSMap pins source lookup to its scan root; Pentest Evidence CLI pins an evidence root for a collection; ProofGraph protects input ancestors. These statements apply to the named implementations, not to unrelated features of every tool.

The local qualification included native atomic directory/symlink exchange tests. Across the six affected output CLIs, the final independent run observed zero redirected files in 600 attempts. Input exchange regressions, FIFO rejection, normal nested paths, Unicode, permissions, non-overwrite behavior, and diagnostic privacy were also exercised where applicable.

This bounds the claim to the tested behavior. It does not promise a filesystem snapshot, protection against privileged mount changes, relocation of an already-open directory inode, or hostile modification by the same user inside a trusted directory. Use physical directory paths instead of symlink aliases.

## Distribution limits

The macOS ARM64 binary is ad-hoc linker-signed and is not Developer ID signed or notarized. No native Windows or Linux release claim is made. Checksums do not prove publisher identity. The project remains a release candidate with the limitations documented in README and SECURITY.
