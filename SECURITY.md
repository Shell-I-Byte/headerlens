# Security policy

Use this tool only with systems and data you own or are explicitly authorized to assess. Do not place credentials, tokens, customer evidence, or personal information in public issues.

## Report a vulnerability

Use [GitHub private vulnerability reporting](https://github.com/Shell-I-Byte/headerlens/security/advisories/new). Include a minimal synthetic reproduction, affected version, expected behavior, and observed behavior. Do not test the issue against third-party systems.

This is a release candidate; no stable security-support window or response-time guarantee is promised. A passing test suite is bounded evidence, not a guarantee that all defects are absent.

## Trust boundaries

Only inspect targets you own or have explicit permission to assess. A missing header is an observation, not proof of an exploitable vulnerability.

Checksums establish integrity relative to the recorded bytes, not publisher identity. The macOS release is locally tested and ad-hoc signed, but not notarized. Native Linux and Windows runtime qualification is not included in this release. Input data, authorization assertions, evidence provenance, and operating-system trust remain the operator’s responsibility.
