"""Falsify semantically impossible HeaderLens v15 redaction claims.

The v15 observation SHA-256 is not a signature. These tests deliberately
recompute valid digests over synthetic contradictory evidence to prove that
contract validation must be separate from digest consistency.
"""
import base64
import copy
import hashlib
import json
import unittest
from pathlib import Path
from verify_evidence_v13 import digest_object, go_json_marshal, verify, VerificationError
from verify_evidence_v15 import verify_v15

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "testdata/evidence"


def loaded(name):
    return json.loads((FIXTURES / name).read_text(encoding="utf-8"))


def resign(obj):
    projection = digest_object(obj, required_schema="headerlens.result/v15")
    obj["evidence_sha256"] = hashlib.sha256(go_json_marshal(projection)).hexdigest()
    return obj


class RedactionContractTests(unittest.TestCase):
    def test_all_original_v15_real_cli_fixtures(self):
        for path in sorted(FIXTURES.glob("v15_*.json")):
            with self.subTest(path=path.name):
                obj = loaded(path.name)
                self.assertTrue(verify_v15(obj)[0])

    def test_raw_auth_value_even_with_matching_digest_must_fail(self):
        obj = loaded("v15_auth_response.json")
        obj["headers"]["Authentication-Info"] = ["nextnonce=PRIVATE_TEST_VALUE"]
        resign(obj)
        self.assertTrue(verify(obj, required_schema="headerlens.result/v15")[0])
        with self.assertRaisesRegex(VerificationError, "v15 redaction"):
            verify_v15(obj)

    def test_six_standard_auth_fields_casefolded(self):
        for field in ("Authentication-Info", "Proxy-Authentication-Info", "Authorization", "Proxy-Authorization", "WWW-Authenticate", "Proxy-Authenticate"):
            with self.subTest(field=field):
                obj = loaded("v15_basic.json")
                obj["headers"][field.lower()] = ["challenge=PRIVATE_TEST_VALUE"]
                resign(obj)
                self.assertTrue(verify(obj, required_schema="headerlens.result/v15")[0])
                with self.assertRaises(VerificationError):
                    verify_v15(obj)

    def test_redirect_and_interim_auth_not_exempt(self):
        for file, collection in (("v15_followed_redirect.json", "redirect_responses"),
                                 ("v15_early_hints.json", "interim_responses")):
            with self.subTest(file=file):
                obj = loaded(file)
                obj[collection][0]["headers"]["Authentication-Info"] = ["nonce=PRIVATE_TEST_VALUE"]
                resign(obj)
                self.assertTrue(verify(obj, required_schema="headerlens.result/v15")[0])
                with self.assertRaises(VerificationError):
                    verify_v15(obj)

    def test_raw_auth_opaque_bytes_mirror_must_fail(self):
        obj = loaded("v15_auth_invalid_utf8.json")
        obj["header_bytes_b64"] = {"Authentication-Info": [base64.b64encode(b"nextnonce=PRIVATE_TEST_VALUE").decode()]}
        resign(obj)
        self.assertTrue(verify(obj, required_schema="headerlens.result/v15")[0])
        with self.assertRaises(VerificationError):
            verify_v15(obj)

    def test_non_boolean_redaction_flag_rejected(self):
        obj = loaded("v15_auth_response.json")
        obj["headers_redacted"] = "true"
        resign(obj)
        self.assertTrue(verify(obj, required_schema="headerlens.result/v15")[0])
        with self.assertRaises(VerificationError):
            verify_v15(obj)

    def test_unredacted_opt_in_does_not_require_placeholder(self):
        obj = loaded("v15_auth_response.json")
        obj["headers_redacted"] = False
        obj["headers"]["Authentication-Info"] = ["nextnonce=synthetic"]
        resign(obj)
        self.assertTrue(verify_v15(obj)[0])


if __name__ == "__main__":
    unittest.main()
