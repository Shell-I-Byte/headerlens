"""Offline CI contract checks: prevents stale Go security patches and skipped native release jobs.

This validates repository configuration, not the execution of GitHub Actions.
"""
from pathlib import Path
import re
import unittest

CI = Path(__file__).resolve().parents[1] / '.github' / 'workflows' / 'ci.yml'
CURRENT = ('1.26.9', '1.27.2')  # confirmed Go security releases, 2026-10-08


class ReleaseCIContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.content = CI.read_text(encoding='utf-8')

    def test_supported_patched_go_matrix(self):
        self.assertRegex(self.content, r"go: \['1\.26\.9', '1\.27\.2'\]")
        self.assertNotIn('1.26.8', self.content)
        self.assertNotIn('1.27.1', self.content)

    def test_analyzer_and_native_toolchains_on_current_patch(self):
        self.assertEqual(2, self.content.count("go-version: '1.27.2'"))
        self.assertIn('honnef.co/go/tools/cmd/staticcheck@v0.8.2', self.content)
        self.assertIn('golang.org/x/vuln/cmd/govulncheck@v1.9.0', self.content)

    def test_native_jobs_run_for_every_push_pr_and_dispatch(self):
        self.assertRegex(self.content, r"(?m)^  push:\s*$")
        self.assertRegex(self.content, r"(?m)^    tags: \['v1\.\*'\]")
        # Release qualification must run before a tag; a v1 tag is too late
        # to discover platform failures and a workflow_dispatch is not proof.
        match = re.search(r'(?ms)^  native_smoke:\n(.*?)(?=^  [A-Za-z_-]+:\n|\Z)', self.content)
        self.assertIsNotNone(match, 'native_smoke job must exist')
        self.assertNotRegex(match.group(1), r'(?m)^    if:', 'native job must not be conditional on a tag')
        self.assertIn('Native compiled CLI positive and adversarial flag checks', match.group(1))
        self.assertIn('tools/native_flag_security_probe.py', match.group(1))
        self.assertIn('go build -trimpath -buildvcs=false -o', match.group(1))
        self.assertIn('workflow_dispatch:', self.content)
        self.assertIn('ubuntu-24.04-arm', self.content)
        self.assertIn('expected_goarch: arm64', self.content)
        self.assertGreaterEqual(self.content.count('go test -race'), 2)
        self.assertIn('macos-15', self.content)
        self.assertIn('windows-2025', self.content)
        self.assertIn('test "$actual_goos" = "$EXPECTED_GOOS"', self.content)
        self.assertIn('test "$actual_goarch" = "$EXPECTED_GOARCH"', self.content)

    def test_dependencies_pinned_to_full_hashes(self):
        uses = re.findall(r'(?m)^\s+- uses: (\S+)(?:\s+#.*)?$', self.content)
        self.assertGreaterEqual(len(uses), 6)
        for u in uses:
            self.assertRegex(u, r'^[^\s@]+@(?:[0-9a-f]{40})$')

    def test_independent_sealed_source_control(self):
        self.assertIn('verify_release_manifest.py --sealed', self.content)
        self.assertIn('verify_source_archive.py', self.content)
        self.assertIn('python3 -m unittest discover', self.content)
        self.assertIn('go test -race', self.content)
        self.assertIn('--expected-version 0.1.21-rc11', self.content)


if __name__ == '__main__':
    unittest.main()
