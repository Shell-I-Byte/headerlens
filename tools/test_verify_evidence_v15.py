"""No external dependencies: independent v15 verifier controls."""
import copy
import json
import unittest
from pathlib import Path
from verify_evidence_v13 import verify, VerificationError, reject_duplicate

ROOT = Path(__file__).resolve().parents[1]
FILES = tuple(sorted((ROOT/'testdata/evidence').glob('v15_*.json')))


class V15EvidenceTests(unittest.TestCase):
    def test_all_five_actual_go_cli_fixtures_verify(self):
        self.assertEqual(len(FILES), 5)
        for path in FILES:
            with self.subTest(path=path.name):
                obj = json.loads(path.read_text(), object_pairs_hook=reject_duplicate)
                self.assertEqual(obj['schema_version'], 'headerlens.result/v15')
                self.assertTrue(verify(obj, required_schema='headerlens.result/v15')[0])

    def test_sensitive_values_are_absent_from_fixture_evidence(self):
        for path in FILES:
            with self.subTest(path=path.name):
                self.assertNotIn('SYNTH_AUTH_TOKEN_FOR_LOCAL_PROBE_72',path.read_text())

    def test_historical_schema_is_not_accepted(self):
        obj=json.loads(FILES[0].read_text())
        with self.assertRaises(VerificationError):
            verify(obj, required_schema='headerlens.result/v14')

    def test_hash_bound_redacted_marker_mutation_is_detected(self):
        obj=json.loads((ROOT/'testdata/evidence/v15_auth_response.json').read_text())
        self.assertTrue(verify(obj, required_schema='headerlens.result/v15')[0])
        bad=copy.deepcopy(obj)
        bad['headers']['Authentication-Info'][0]='<tampered>'
        self.assertFalse(verify(bad, required_schema='headerlens.result/v15')[0])

    def test_hash_not_signature_and_unbound_findings_remain_unprotected(self):
        obj=json.loads((ROOT/'testdata/evidence/v15_auth_response.json').read_text())
        tampered=copy.deepcopy(obj)
        tampered['findings'].append({'id':'MADE-UP', 'title':'Unverified', 'severity':'PASS', 'category':'unsafe'})
        self.assertTrue(verify(tampered, required_schema='headerlens.result/v15')[0])

    def test_duplicate_json_keys_are_rejected_before_verification(self):
        with self.assertRaises(VerificationError):
            json.loads('{"a":1,"a":2}',object_pairs_hook=reject_duplicate)

if __name__=='__main__': unittest.main()
