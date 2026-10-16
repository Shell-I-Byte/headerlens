> Current public release and Mac validation status: [README](../README.md) and [MACOS_QUALIFICATION.md](MACOS_QUALIFICATION.md). Historical run references in this technical document do not describe the current publication status.

# HeaderLens v0.1.20 release candidate — 2026-10-08

Release **candidate only**. Terminal-safe text formatting now consistently encodes control and bidi code points in every displayed finding/TLS field. A failing synthetic test on v0.1.19, and a passing regression on v0.1.20, demonstrate BUG-HL-074. Default analyzer finding titles are constants, so an externally reachable exploit was not established. JSON, v1–v15 schemas, proofgraph ingest contract and evidence SHA-256 digests are unchanged.

The following *release gates are NOT satisfied in this environment*: supported Go 1.26.8/1.27.1 compile/test/race; Staticcheck v0.8.1; govulncheck v1.8.0; published GitHub CI; native macOS and Windows runtime. The bundled CI workflow has not run on GitHub. Do not describe this package as stable/production certified.
