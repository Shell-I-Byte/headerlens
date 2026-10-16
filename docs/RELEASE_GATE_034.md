> Current public release and Mac validation status: [README](../README.md) and [MACOS_QUALIFICATION.md](MACOS_QUALIFICATION.md). Historical run references in this technical document do not describe the current publication status.

# Release gate / audit round 034 (2026-10-08)

Version stays **v0.1.20 RC**, result contract `headerlens.result/v15` unchanged; no runtime application code modified. The independently re-read run024 sealed source archive contained four generated CPython 3.13 `.pyc` entries in its manifest, whereas the local Git bundle excluded them. These files were not product runtime dependencies, but this is a material source-release hygiene/identity failure. This round removes those build byproducts, checks all manifest digest entries and aligns sealed source file inventory with tracked Git source. A small offline manifest verifier and positive/negative regression tests were added; its test is included in the existing Python unittest CI discovery. These checks prevent both untracked source inclusion and stale digest acceptance.

Go suites (test/race/shuffle/vet/build/mod verify) were run with local **unsupported Go 1.23.2 Linux/amd64**, plus Python evidence tests and sealed source tests. Cross-compiles on Linux to macOS ARM64 and Windows AMD64 are NOT native runtime evidence.

**Still blocked**: tests on supported Go 1.26.8 and 1.27.1; actual Staticcheck v0.8.1 and govulncheck v1.8.0; uploaded GitHub source and successful CI jobs; native macOS and Windows executions. The connected repository list still did not include `077-Protocol/headerlens`. No publication permission; no GitHub write. Do not promote to stable v1 without the required evidence. Historical repaired-root-cause count from previous logs has not been independently re-verified here.

Archive input lineage: HeaderLens_v0.1.20_Run024_CIguard_source.zip SHA-256 `66c768b69c0c58fc7dfcca56b6cfb767873f63307523441ee5b9d93a7248c38f`. The original four external SHA-256 sums all verified. ZIP and Git source inventories differed only in the four `.pyc` files; see run034 release audit logs and output for the corrected inventory check.
