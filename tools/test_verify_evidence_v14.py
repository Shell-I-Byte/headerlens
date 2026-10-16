"""Independent v14 digest verification; no extra Python packages."""
import json
import unittest
from pathlib import Path
from verify_evidence_v13 import VerificationError, verify

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = sorted((ROOT / "testdata" / "evidence").glob("v14_*.json"))


def vector(name):
    return json.loads((ROOT / "testdata" / "evidence" / name).read_text(encoding="utf-8"))

class V14VerifierTests(unittest.TestCase):
    def test_all_six_independent_real_go_cli_vectors(self):
        self.assertEqual(len(FIXTURES), 6)
        for path in FIXTURES:
            with self.subTest(path=path.name):
                obj = json.loads(path.read_text(encoding="utf-8"))
                matched, actual, stored = verify(obj, required_schema="headerlens.result/v14")
                self.assertTrue(matched, f"{actual} != {stored}")

    def test_hashed_tls_certificate_tampering_fails(self):
        obj = vector("v14_certificate_failure.json")
        obj["tls"]["cert_sha256"] = "f" * 64
        self.assertFalse(verify(obj, required_schema="headerlens.result/v14")[0])

    def test_hashed_103_response_tampering_fails(self):
        obj = vector("v14_early_hints.json")
        self.assertTrue(obj["interim_responses"])
        obj["interim_responses"][0]["request_index"] = 9
        self.assertFalse(verify(obj, required_schema="headerlens.result/v14")[0])

    def test_hashed_redirect_location_tampering_fails(self):
        obj = vector("v14_followed_redirect.json")
        obj["redirect_chain"][1] += "/tampered"
        self.assertFalse(verify(obj, required_schema="headerlens.result/v14")[0])

    def test_invalid_utf8_byte_mirror_is_bound(self):
        obj = vector("v14_invalid_utf8.json")
        key = next(iter(obj["header_bytes_b64"]))
        obj["header_bytes_b64"][key][0] = "Y2hhbmdlZA=="
        self.assertFalse(verify(obj, required_schema="headerlens.result/v14")[0])

    def test_version_is_rejected_by_wrong_verifier(self):
        obj = vector("v14_basic.json")
        with self.assertRaises(VerificationError):
            verify(obj)

    def test_derived_findings_remain_unbound_by_design(self):
        obj = vector("v14_basic.json")
        obj["findings"] = [{"id":"synthetic","severity":"PASS","category":"not-attested","title":"NOT PROVEN"}]
        self.assertTrue(verify(obj, required_schema="headerlens.result/v14")[0])

    def test_empty_blocked_url_remains_hash_bound(self):
        obj = vector("v14_blocked_redirect.json")
        obj["redirect_blocked"]["url"] = ""
        self.assertFalse(verify(obj, required_schema="headerlens.result/v14")[0])

    def test_evidence_hash_changed_on_schema_upgrade(self):
        old = vector("v13_basic.json")
        new = vector("v14_basic.json")
        self.assertNotEqual(old["schema_version"], new["schema_version"])
        self.assertTrue(verify(old)[0])
        self.assertTrue(verify(new, required_schema="headerlens.result/v14")[0])

    def test_consumed_empty_http_version_bound(self):
        obj = vector("v14_certificate_failure.json")
        self.assertEqual(obj["http_version"], "")
        self.assertTrue(verify(obj, required_schema="headerlens.result/v14")[0])
        obj.pop("http_version")
        self.assertFalse(verify(obj, required_schema="headerlens.result/v14")[0])

if __name__ == "__main__":
    unittest.main()
