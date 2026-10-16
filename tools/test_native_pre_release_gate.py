"""Mandatory native CI release gate: static contracts, not a claim of execution.

Run this with the old workflow to reproduce the missing pre-release gate.
"""
from pathlib import Path
import re
import unittest

CI = Path(__file__).resolve().parents[1] / '.github/workflows/ci.yml'


class NativeBeforeReleaseTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.config = CI.read_text(encoding='utf-8')
        match = re.search(r'(?ms)^  native_smoke:\n(.*?)(?=^  [A-Za-z_][A-Za-z_0-9-]*:\n|\Z)', cls.config)
        if match is None:
            raise AssertionError('missing native_smoke job')
        cls.job = match.group(1)

    def test_native_platform_jobs_not_conditional_on_tag_or_manual_trigger(self):
        self.assertNotRegex(self.job, r'(?m)^    if:')
        self.assertNotIn('workflow_dispatch ||', self.job)
        self.assertIn('pull_request:', self.config)
        self.assertIn("tags: ['v1.*']", self.config)

    def test_three_native_architectures_and_exact_patch(self):
        for runner in ('ubuntu-24.04-arm', 'macos-15', 'windows-2025'):
            self.assertIn(runner, self.job)
        for platform in ('linux', 'darwin', 'windows'):
            self.assertIn('expected_goos: '+platform, self.job)
        self.assertIn("go-version: '1.27.2'", self.job)
        self.assertIn('test "$actual_goos" = "$EXPECTED_GOOS"', self.job)
        self.assertIn('test "$actual_goarch" = "$EXPECTED_GOARCH"', self.job)

    def test_positive_and_negative_actual_cli_execution(self):
        self.assertIn('go build -trimpath -buildvcs=false -o "$binary" ./cmd/headerlens', self.job)
        self.assertIn('tools/native_flag_security_probe.py', self.job)
        self.assertIn('go test -race -count=1 ./...', self.job)
        self.assertIn('go mod verify', self.job)


if __name__ == '__main__':
    unittest.main()
