"""Versioned cross-language digest agreement tests; stdlib-only."""
import json
import unittest
from pathlib import Path

from verify_evidence_v13 import (
    VerificationError, digest_object, go_json_marshal, reject_duplicate,
    verify,
)

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = sorted((ROOT / "testdata" / "evidence").glob("v13_*.json"))

class VerifierTests(unittest.TestCase):
    def fixtures(self):
        for path in FIXTURES:
            yield path.name, json.loads(path.read_text(encoding="utf-8"))

    def test_real_go_cli_fixture_digests_match(self):
        self.assertEqual(len(FIXTURES), 6)
        for name, obj in self.fixtures():
            with self.subTest(name=name):
                matched, calculated, recorded = verify(obj)
                self.assertTrue(matched, f"{name}: {calculated} != {recorded}")

    def test_mutating_hashed_headers_is_detected(self):
        obj = json.loads((ROOT / "testdata/evidence/v13_basic.json").read_text())
        obj["headers"]["Content-Type"][0] = "injected"
        self.assertFalse(verify(obj)[0])

    def test_mutating_hashed_tls_cert_is_detected(self):
        obj = json.loads((ROOT / "testdata/evidence/v13_certificate_failure.json").read_text())
        obj["tls"]["cert_sha256"] = "0" * 64
        self.assertFalse(verify(obj)[0])

    def test_mutating_hashed_invalid_utf8_byte_mirror_is_detected(self):
        obj = json.loads((ROOT / "testdata/evidence/v13_invalid_utf8.json").read_text())
        key = next(iter(obj["header_bytes_b64"]))
        obj["header_bytes_b64"][key][0] = "aGVsbG8="
        self.assertFalse(verify(obj)[0])

    def test_unbound_findings_are_not_authenticated(self):
        obj = json.loads((ROOT / "testdata/evidence/v13_basic.json").read_text())
        self.assertTrue(verify(obj)[0])
        obj["findings"] = [{"id":"fake","severity":"PASS","title":"UNPROVEN!","category":"x"}]
        self.assertTrue(verify(obj)[0], "the v13 hash intentionally does not bind findings")
        obj["scanned_at"] = "1990-01-01T00:00:00Z"
        obj["tool_version"] = "untrusted-not-bound"
        self.assertTrue(verify(obj)[0], "timestamp and version are intentionally not bound")

    def test_schema_version_mismatch_is_rejected(self):
        obj = json.loads((ROOT / "testdata/evidence/v13_basic.json").read_text())
        obj["schema_version"] = "headerlens.result/v12"
        with self.assertRaises(VerificationError):
            verify(obj)

    def test_unexpected_fields_are_rejected(self):
        obj = json.loads((ROOT / "testdata/evidence/v13_basic.json").read_text())
        obj["falsified_authorization"] = "permit"
        with self.assertRaises(VerificationError):
            verify(obj)

    def test_duplicate_key_is_rejected(self):
        with self.assertRaises(VerificationError):
            json.loads('{"evidence_sha256":"a","evidence_sha256":"b"}',object_pairs_hook=reject_duplicate)

    def test_empty_required_http_version_is_hash_bound(self):
        obj = json.loads((ROOT / "testdata/evidence/v13_certificate_failure.json").read_text())
        self.assertEqual(obj["http_version"], "")
        self.assertTrue(verify(obj)[0])
        del obj["http_version"]
        self.assertFalse(verify(obj)[0])

    def test_html_escaping_matches_go_encoding_json(self):
        b = go_json_marshal({"x": "a<>&\u2028\u2029"})
        self.assertEqual(b, b'{"x":"a\\u003c\\u003e\\u0026\\u2028\\u2029"}')

if __name__ == "__main__":
    unittest.main()
