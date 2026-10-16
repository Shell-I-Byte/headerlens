> Current public release and Mac validation status: [README](../README.md) and [MACOS_QUALIFICATION.md](MACOS_QUALIFICATION.md). Historical run references in this technical document do not describe the current publication status.

# HeaderLens v0.1.21-rc8 — 2026-10-13 (prerelease)

Release-process security fix BUG-HL-140-001: the pre-extraction source-ZIP verifier
accepted SHA-256-manifested entries whose filenames are reserved Win32 device names
(e.g. `NUL.txt`, `COM1.txt`, including nested aliases), as well as other Windows-
invalid characters. Such archives are valid on Linux but cannot be extracted and
rechecked portably across supported platforms. This was independently reproduced
on the sealed RC7 verifier with an archive containing a fully SHA-256-matched
`fixture/NUL.txt` entry; RC7 returned success. RC8 checks every ZIP member and
manifest path component, rejecting device aliases, invalid punctuation and C0/DEL
controls, including root names, before extraction. Positive/negative controls
are included in `tools/test_verify_source_archive.py`.

No analyzer algorithm, HTTP request behavior, Go dependency, or evidence digest
contract changed. `headerlens.result/v15` remains unchanged. Existing issued RC7
ZIPs keep their original SHA-256; do not relabel them. RC8 has new source and
binary hashes and separate local Git provenance.

The supported Go 1.26.9/1.27.2 matrix, Staticcheck, Govulncheck, hosted CI and
native macOS/Windows tests remain NOT EXECUTED or BLOCKED until a properly
permitted standalone repository or suitable runner is available.
