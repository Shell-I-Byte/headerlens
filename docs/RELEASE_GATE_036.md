> Current public release and Mac validation status: [README](../README.md) and [MACOS_QUALIFICATION.md](MACOS_QUALIFICATION.md). Historical run references in this technical document do not describe the current publication status.

# HeaderLens release gate audit 036 (2026-10-08)

**Status:** v0.1.20 RC; `headerlens.result/v15` unchanged. **No native or hosted release certification.**

## Confirmed false pass and correction

A valid source-manifest fixture with a foreign, untracked `tools/__pycache__/foreign.pyc` produced `validate(root) == []`. The existing validator deliberately ignores Python build caches in a development checkout, but a sealed distributable ZIP must not silently accept extra payloads under excluded paths. This is a **release verifier** failure, not a scanner HTTP runtime defect or proof of any malicious file in the previously distributed archive.

A separate `--sealed` mode now rejects *all* extra non-source files and symlinks in a freshly extracted sealed source folder. Default checkout mode still tolerates generated Python caches, so ordinary local work remains practical. Independent positive, negative, boundary and hidden-file controls were added to `tools/test_release_manifest.py`. CI additionally seals the tracked source, extracts it to a temporary directory and strictly checks the resulting source tree.

**Run on a clean extracted source ZIP, before running Python tests:**

```bash
python3 tools/verify_release_manifest.py --sealed /path/to/extracted/HeaderLens_v0.1.20
```

For development checkout only, run `python3 tools/verify_release_manifest.py` (without `--sealed`). The strict tree check is NOT a substitute for independent ZIP CRC/unsafe member checks, comparison to a Git snapshot, SHA-256 or runtime tests.

## Gates not yet satisfied

Go 1.26.8/1.27.1, Staticcheck v0.8.1, govulncheck v1.8.0 and native GitHub Actions/Windows/macOS are still BLOCKED/NOT RUN. No GitHub repo/publication was created. Current machine Go 1.23.2 is a compatibility test only. Existing `-buildvcs=false` reproducible build recipe preserved.

Provenance: prior HeaderLens v0.1.20 Run035 source ZIP + Git bundle, SHA256SUMS checks, clean clone, new source commit and regenerated independent ZIP manifest; no external scanner targets. See `audits/run036/` for individual tickets.
