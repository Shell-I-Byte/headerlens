> Current public release and Mac validation status: [README](../README.md) and [MACOS_QUALIFICATION.md](MACOS_QUALIFICATION.md). Historical run references in this technical document do not describe the current publication status.

# HeaderLens v0.1.21-rc2 — audit Run058 (2026-10-09)

## Decision
**RC only. Stable v1 blocked.** A real test instability was reproduced under Go 1.23.2; the product's evidence hashing is correct when the observed server `Date` changes.

## Positive controls and falsification
- Original Run051 sealed ZIP, Git bundle and SHA256SUMS independently compared and verified.
- Original flaky test failed in the available full suite and again in `go test -count=40` trials.
- Instrumented reproduction recorded first response `Date: Fri, 09 Oct 2026 14:15:41 GMT` and divergent response `Date: Fri, 09 Oct 2026 14:15:42 GMT`; hashes differed as expected.
- Corrected test freezes the synthetic response `Date`, leaving the production analyzer intact; new regression explicitly requires distinct Date values to change the evidence SHA.
- Synthetic localhost 103 Early Hints flood tests: five were preserved, six or more were safely rejected by current Go net/http; not a confirmed unbounded-memory issue in the current test environment.

## Mandatory unresolved release gates
- Run both Go 1.26.9 and 1.27.2 suites in supported Linux, plus quality analyzers Staticcheck v0.8.1 / govulncheck v1.8.0.
- Observe actual GitHub Actions run IDs and completion; native macOS arm64 / Windows amd64 results required. Offline Linux crosscompiles are not native testing.
- No GitHub publication without explicit permission; source and complete local Git bundle suffice for offline handoff.
