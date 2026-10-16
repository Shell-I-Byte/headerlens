"""Black-box privacy regressions for all shipped evidence verifiers.

These fixtures use synthetic sentinel strings, not production secrets.
"""
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
VERSIONS = (13, 14, 15)
SENTINEL = "LOCAL_SYNTHETIC_SECRET_DO_NOT_LOG_RUN077_X9"


class VerifierDiagnosticPrivacyTests(unittest.TestCase):
    def execute_verifier(self, version, json_text):
        with tempfile.TemporaryDirectory() as dirname:
            input_file = Path(dirname) / "input.json"
            input_file.write_text(json_text, encoding="utf-8")
            script = ROOT / "tools" / f"verify_evidence_v{version}.py"
            return subprocess.run(
                [sys.executable, str(script), str(input_file)],
                capture_output=True, text=True, timeout=10, check=False,
            )

    def test_duplicate_untrusted_keys_never_reach_diagnostics(self):
        for version in VERSIONS:
            with self.subTest(version=version):
                payload = '{"%s":1,"%s":2}' % (SENTINEL, SENTINEL)
                proc = self.execute_verifier(version, payload)
                self.assertEqual(proc.returncode, 2)
                self.assertNotIn(SENTINEL, proc.stderr + proc.stdout)

    def test_unsupported_untrusted_keys_never_reach_diagnostics(self):
        for version in VERSIONS:
            with self.subTest(version=version):
                payload = {"schema_version": f"headerlens.result/v{version}", SENTINEL: 1}
                proc = self.execute_verifier(version, json.dumps(payload))
                self.assertEqual(proc.returncode, 2)
                self.assertNotIn(SENTINEL, proc.stderr + proc.stdout)

    def test_untrusted_digest_value_never_reaches_mismatch_diagnostics(self):
        for version in VERSIONS:
            with self.subTest(version=version):
                sample = ROOT / "testdata" / "evidence" / f"v{version}_auth_response.json"
                if not sample.exists():
                    samples = sorted((ROOT / "testdata" / "evidence").glob(f"v{version}_*.json"))
                    self.assertTrue(samples, f"expected v{version} sample")
                    sample = samples[0]
                payload = json.loads(sample.read_text(encoding="utf-8"))
                payload["evidence_sha256"] = SENTINEL
                proc = self.execute_verifier(version, json.dumps(payload))
                self.assertNotEqual(proc.returncode, 0)
                self.assertNotIn(SENTINEL, proc.stderr + proc.stdout)

    def test_good_existing_fixtures_remain_accepted(self):
        for version in VERSIONS:
            with self.subTest(version=version):
                files = sorted((ROOT / "testdata" / "evidence").glob(f"v{version}_*.json"))
                self.assertTrue(files)
                proc = self.execute_verifier(version, files[0].read_text(encoding="utf-8"))
                self.assertEqual(proc.returncode, 0, proc.stderr)
                self.assertIn("MATCH", proc.stdout)


if __name__ == "__main__":
    unittest.main()
