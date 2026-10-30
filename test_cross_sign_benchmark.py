#!/usr/bin/env python3
"""Offline cross-sign protocol/audit controls; no device or remote writes."""
import importlib.util
import base64
import json
from pathlib import Path
import tempfile
import unittest

from jwcrypto import jwk, jws

ROOT = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location("cross_sign_protocol", ROOT / "run-cross-sign-benchmark.py")
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)
SUMMARY = MODULE.load("cross_sign_independent_summary", "summarize-cross-sign-results.py")
SIGNING = MODULE.load("cross_sign_unit_signing", "generate-lifecycle-artifacts.py")


class CrossSignBenchmarkTest(unittest.TestCase):
    def test_six_cases_and_two_same_leaf_paths(self):
        cases = MODULE.cases()
        self.assertEqual(len(cases), 6)
        self.assertEqual(len({case[0] for case in cases}), 6)
        self.assertEqual(sum(case[4] for case in cases), 3)
        self.assertEqual({case[2] for case in cases[:4]}, {"leaf.key"})
        self.assertEqual(cases[1][3:5], ("direct-b.pem", False))
        self.assertEqual(cases[-1][4:6], (False, True))

    def test_audit_exact_unique_request_tags(self):
        def event(i): return {"path": "/", "generation": "cs-run", "observation": "cs-run-" + str(i), "status": 200}
        self.assertEqual(len(MODULE.audit_requests([event(0), event(1)], "cs-run", 2, True)), 2)
        for events in ([event(0)], [event(0), event(0)], [event(0), event(2)],
                       [event(0), event(1) | {"status": 503}]):
            with self.subTest(events=events), self.assertRaises(ValueError):
                MODULE.audit_requests(events, "cs-run", 2, True)

    def test_negative_case_cannot_send_business_request(self):
        self.assertEqual(MODULE.audit_requests([], "cs-run", 20, False), [])
        with self.assertRaises(ValueError):
            MODULE.audit_requests([{"path": "/", "generation": "cs-run", "observation": "cs-run-0", "status": 200}],
                                  "cs-run", 20, False)

    def test_metadata_and_unrelated_generations_are_not_business_requests(self):
        events = [{"path": "/.well-known/ServerCertClaim.jws", "generation": "cs-run", "status": 200},
                  {"path": "/", "generation": "another-run", "status": 200}]
        self.assertEqual(MODULE.audit_requests(events, "cs-run", 20, False), [])

    def test_independent_checker_requires_real_policy_signature(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            key = jwk.JWK.generate(kty="EC", crv="P-256")
            private, public = directory / "private.pem", directory / "public.pem"
            private.write_bytes(key.export_to_pem(private_key=True, password=None))
            public.write_bytes(key.export_to_pem())
            payload = {"issuer": ["sha256:allowed"], "iat": 1, "exp": 2}
            value = json.loads(SIGNING.general_jws(payload, [(private, public, "ES256")]))
            token = directory / "claim.jws"
            token.write_text(json.dumps(value))
            self.assertEqual(SUMMARY.signed_payload(token, jwk.JWK.from_pem(public.read_bytes())), payload)
            with self.assertRaises(jws.InvalidJWSSignature):
                SUMMARY.signed_payload(token, jwk.JWK.generate(kty="EC", crv="P-256"))
            value["payload"] = base64.urlsafe_b64encode(b'{"issuer":["sha256:rogue"]}').rstrip(b"=").decode()
            token.write_text(json.dumps(value))
            with self.assertRaises(jws.InvalidJWSSignature):
                SUMMARY.signed_payload(token, key)

    def test_independent_checker_rejects_non_general_serialization(self):
        with tempfile.TemporaryDirectory() as temporary:
            token = Path(temporary) / "flattened.jws"
            token.write_text(json.dumps({"payload": "e30", "signature": "invalid"}))
            with self.assertRaises(ValueError):
                SUMMARY.signed_payload(token, jwk.JWK.generate(kty="EC", crv="P-256"))


if __name__ == "__main__": unittest.main()
