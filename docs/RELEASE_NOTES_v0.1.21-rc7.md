> Current public release and Mac validation status: [README](../README.md) and [MACOS_QUALIFICATION.md](MACOS_QUALIFICATION.md). Historical run references in this technical document do not describe the current publication status.

# HeaderLens v0.1.21-rc7 (2026-10-12)

Prerelease. Run 129 fixes the confirmed **release-process** gap from audit 128:
ZIP-container contents could include a sibling outside the directory scope
of the original extracted-source manifest checker. The official source package
now includes `tools/verify_source_archive.py`, regression tests, and a CI
step rejecting unwanted members *before* extraction. The prior manifest
verifier remains as a second check after extraction.

The analyzer behavior is unchanged, the JSON contract is still
`headerlens.result/v15`, and existing source/binary consumers need no schema
migration. The CLI identifies itself as 0.1.21-rc7.

Supported Go toolchain, Staticcheck, Govulncheck, hosted GitHub Actions and
native macOS/Windows acceptance are still **not proven**. This is not a
stable v1 or a production certification. Embedded checksums are integrity
controls, not an authenticated publisher identity.
