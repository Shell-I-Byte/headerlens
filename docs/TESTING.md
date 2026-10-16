> Current public release and Mac validation status: [README](../README.md) and [MACOS_QUALIFICATION.md](MACOS_QUALIFICATION.md). Historical run references in this technical document do not describe the current publication status.

# Testing

## Recorded RC6 acceptance

The original RC6 source snapshot is commit
`581de733d2126eb482eba57b6a98905b276f8415`.
Its source archive SHA-256 is
`c5b047a538d5af0b07d07e695f7af18bf66708d3c741b270a432779a7da31248`.

The public source snapshot retains all Go production files, Go tests and Python
test/verifier files byte-for-byte. README, release notes, this testing document
and the source manifest are publication documentation changes.

The recorded Linux AMD64 executable has SHA-256
`aa9faffdb5e560b1bbaebe795d5f6903346aa745f2bbbf02e5299579175a8948`.
Compiler: Go 1.23.2. Build: `CGO_ENABLED=0`, `GOAMD64=v1`,
`-trimpath -buildvcs=false`.

The 16-scenario acceptance suite was executed on independently built ZIP and Git
source copies, then on a fresh extraction of the delivered lab package. Each run
completed with no failures, errors or skips. The suite invokes the real CLI,
starts only loopback servers, and checks result content rather than exit codes alone.

It covers missing and correctly configured headers, trusted and untrusted TLS,
cookie/authentication redaction, explicit sensitive-output opt-in, blocked and
allowed redirects, timeouts, oversized headers, malformed arguments and URLs,
concurrent observations, digest tampering, the documented unbound-findings
limitation, HTTP 103, IPv6 loopback and failed output writes.

The ordinary, race and shuffled Go suites, `go vet`, `go build`, `go mod verify`,
47 Python unit tests and the CLI argument tests also passed in the recorded runs.

## Limits of these results

Go 1.23.2 is no longer supported. Attempts to obtain supported toolchains and
Staticcheck/Govulncheck failed in the local test environment. No completed
vulnerability scan or hosted CI success is claimed here.

Only Linux AMD64 runtime behavior is established. Cross-compilation is not a
native macOS, Windows or ARM64 test. These results do not establish behavior on
another machine or against untested inputs.

The CI workflow contains pinned supported-toolchain and analyzer jobs. Native
smoke jobs also run when the workflow is manually dispatched. Their results must
be inspected before they can be treated as evidence.

Use the supplied binary only for the included local lab tests, not live security
assessments. Matching hashes establish internal consistency, not publisher
authentication. The MIT license supplies no warranty.


### Run 129 source-archive preflight (2026-10-12)

Before extracting a sealed release source ZIP:

```sh
python3 tools/verify_source_archive.py /path/to/HeaderLens_source.zip
python3 -B -m unittest discover -s tools -p "test_verify_source_archive.py" -v
```

The validator binds ZIP membership and file data to the source manifest
*inside* that ZIP, with bounded reads and negative controls for untrusted
archive shapes. It does not supply cryptographic publisher authentication.
The `ci.yml` release seal step invokes it before `unzip`, then also validates
the extracted source tree. Actual hosted CI success is still UNTESTED.

### Run 154 source ZIP admission boundary (2026-10-13)

Run `python3 -B -m unittest discover -s tools -p 'test_verify_source_archive.py' -v` to test source ZIP safety. Negative controls include fully manifested `.git` control paths, directory-prefix case aliases, and regular file/directory collisions. A matching manifest demonstrates internal agreement only; issuer authentication must use an independently trusted signature/digest. See `audits/run154`. Native Windows/macOS and current Go/Staticcheck/Govulncheck gates are not satisfied merely by these Python tests.
