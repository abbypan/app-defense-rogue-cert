#!/usr/bin/env python3
"""Disposable host regression tests; no Android performance measurements."""

import base64
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from jwcrypto import jwk, jws

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT / 'signing'))
from issuer_policy import direct_issuer_certificates


def load_module(name, filename):
    spec = importlib.util.spec_from_file_location(name, ROOT / filename)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


fixtures_module = load_module('cross_sign_fixtures', 'generate-cross-sign-fixtures.py')
validator = load_module('cross_sign_validator', 'check-trust-artifacts.py')
artifacts = load_module('cross_sign_artifacts', 'generate-lifecycle-artifacts.py')
summary = load_module('cross_sign_summary', 'summarize-lifecycle-results.py')


class CrossSignTest(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.fixtures = self.root / 'fixtures'
        self.certs = fixtures_module.generate(self.fixtures)

    def verify_path(self, leaf, direct, roots='trusted-roots.pem', hostname='cross-sign.example'):
        return subprocess.run(['openssl', 'verify', '-show_chain', '-no-CAfile',
            '-no-CApath', '-no-CAstore', '-trusted', str(self.fixtures / roots),
            '-untrusted', str(self.fixtures / direct), '-verify_hostname', hostname,
            str(self.fixtures / leaf)], capture_output=True, text=True)

    def test_identical_leaf_two_native_valid_paths(self):
        first, second = self.certs['direct-a.pem'], self.certs['direct-b.pem']
        self.assertEqual(first.subject, second.subject)
        self.assertEqual(first.public_key().public_numbers(), second.public_key().public_numbers())
        self.assertNotEqual(first.public_bytes(serialization.Encoding.DER), second.public_bytes(serialization.Encoding.DER))
        self.assertNotEqual(validator.issuer_identifier(first), validator.issuer_identifier(second))
        for direct, root in (('direct-a.pem', 'root-a.pem'), ('direct-b.pem', 'root-b.pem')):
            result = self.verify_path('leaf.pem', direct, root)
            self.assertEqual(result.returncode, 0, result.stderr)

    def test_fixture_regeneration_never_overwrites_existing_material(self):
        before = (self.fixtures / 'leaf.pem').read_bytes()
        with self.assertRaises(FileExistsError):
            fixtures_module.generate(self.fixtures)
        self.assertEqual((self.fixtures / 'leaf.pem').read_bytes(), before)

    def test_all_variants_not_ancestors_or_duplicates(self):
        candidates = x509.load_pem_x509_certificates((self.fixtures / 'issuer-variants.pem').read_bytes())
        selected = direct_issuer_certificates(self.certs['leaf.pem'], candidates)
        self.assertEqual([validator.issuer_identifier(cert) for cert in selected],
            [validator.issuer_identifier(self.certs[name]) for name in ('direct-a.pem', 'direct-b.pem')])

    def test_full_set_accepts_both_but_incomplete_rejects_b(self):
        a, b = (validator.issuer_identifier(self.certs[name]) for name in ('direct-a.pem', 'direct-b.pem'))
        self.assertIn(a, {a, b}); self.assertIn(b, {a, b})
        self.assertNotIn(b, {a})
        self.assertNotEqual(self.verify_path('leaf.pem', 'direct-b.pem', 'root-a.pem').returncode, 0)

    def test_same_name_ca_does_not_enter_allowlist(self):
        self.assertEqual(self.certs['rogue-direct.pem'].subject, self.certs['direct-a.pem'].subject)
        result = self.verify_path('rogue-leaf.pem', 'rogue-direct.pem')
        self.assertEqual(result.returncode, 0, result.stderr)
        selected = direct_issuer_certificates(self.certs['leaf.pem'], [
            self.certs['direct-a.pem'], self.certs['rogue-direct.pem'], self.certs['direct-b.pem']])
        self.assertEqual(len(selected), 2)
        self.assertNotIn(validator.issuer_identifier(self.certs['rogue-direct.pem']),
            {validator.issuer_identifier(cert) for cert in selected})

    def test_padding_cannot_change_the_actual_direct_issuer(self):
        candidates = [self.certs['rogue-direct.pem'], self.certs['direct-a.pem']]
        selected = direct_issuer_certificates(self.certs['rogue-leaf.pem'], candidates)
        self.assertEqual([validator.issuer_identifier(cert) for cert in selected],
            [validator.issuer_identifier(self.certs['rogue-direct.pem'])])

    def test_no_matching_direct_issuer_is_error(self):
        with self.assertRaises(ValueError):
            direct_issuer_certificates(self.certs['leaf.pem'], [self.certs['root-a.pem']])

    def test_device_summary_requires_path_and_rejection_evidence(self):
        target = self.root / 'results' / 'artifacts' / 'cross-sign'
        target.mkdir(parents=True)
        for source in self.fixtures.glob('*.pem'):
            shutil.copyfile(source, target / source.name)
        row = dict(Attempt='0', Native_Valid='true',
            Selected_Issuer=validator.issuer_identifier(self.certs['rogue-direct.pem']),
            Leaf_Digest=validator.issuer_identifier(self.certs['rogue-leaf.pem']),
            Extra_Seen='true', Policy_Checked='true', Policy_Rejected='true',
            Accepted='false', App_Request_Sent='false', Result='PASS')
        root = self.root / 'results'
        summary.validate_cross_sign([row], 'cross-sign-padding-rejected.csv', root)
        for field, wrong in (('Native_Valid', 'false'), ('Selected_Issuer', 'wrong'),
                             ('Extra_Seen', 'false'), ('Policy_Rejected', 'false'),
                             ('App_Request_Sent', 'true'), ('Leaf_Digest', 'wrong')):
            with self.subTest(field=field), self.assertRaises(ValueError):
                summary.validate_cross_sign([dict(row, **{field: wrong})],
                    'cross-sign-padding-rejected.csv', root)

    def test_generated_lifecycle_policies_are_distinct_versions(self):
        signing = self.root / 'es256'
        signing.mkdir()
        key = ec.generate_private_key(ec.SECP256R1())
        (signing / 'my-claim-key.pem').write_bytes(key.private_bytes(serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
        (signing / 'my-claim-pubkey.pem').write_bytes(key.public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo))
        encoded = base64.urlsafe_b64encode(json.dumps({'iat': 1}).encode()).rstrip(b'=').decode()
        (signing / 'ServerCertClaim.jws').write_text(json.dumps({'payload': encoded}))
        output = self.root / 'policies'
        artifacts.generate_cross_sign(SimpleNamespace(signing_dir=signing,
            fixture_dir=self.fixtures, output_dir=output, ttl=300))
        first = artifacts.decode_payload(output / 'tc-incomplete.jws')
        second = artifacts.decode_payload(output / 'tc-complete.jws')
        self.assertGreater(second['iat'], first['iat'])
        self.assertEqual(len(first['issuer']), 1)
        self.assertEqual(len(second['issuer']), 2)
        self.assertEqual(first['subject'], second['subject'])
        self.assertEqual(first['san'], second['san'])

    def test_real_general_jws_signers_include_both_der_ids(self):
        profiles = [('es256', ec.generate_private_key(ec.SECP256R1())),
                    ('es384', ec.generate_private_key(ec.SECP384R1())),
                    ('rsa3072', rsa.generate_private_key(65537, 3072)),
                    ('rsa4096', rsa.generate_private_key(65537, 4096))]
        for variant, key in profiles:
            with self.subTest(variant=variant):
                signing = self.root / variant
                signing.mkdir()
                private = key.private_bytes(serialization.Encoding.PEM,
                    serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
                public = key.public_key().public_bytes(serialization.Encoding.PEM,
                    serialization.PublicFormat.SubjectPublicKeyInfo)
                (signing / 'my-claim-key.pem').write_bytes(private)
                (signing / 'my-claim-pubkey.pem').write_bytes(public)
                for hash_name in ('sha256', 'sha384'):
                    result = subprocess.run([sys.executable,
                        str(ROOT / 'signing' / variant / 'gen_jws_ServerCertClaim.py'),
                        str(self.fixtures / 'leaf.pem'), str(self.fixtures / 'issuer-variants.pem')],
                        cwd=signing, env=dict(os.environ, ASPIN_ISSUER_HASH=hash_name),
                        capture_output=True, text=True)
                    self.assertEqual(result.returncode, 0, result.stderr)
                    token = jws.JWS()
                    token.deserialize((signing / 'ServerCertClaim.jws').read_text())
                    token.verify(jwk.JWK.from_pem(public))
                    payload = json.loads(token.payload)
                    expected = [validator.issuer_identifier(self.certs[name], hash_name)
                                for name in ('direct-a.pem', 'direct-b.pem')]
                    self.assertEqual(payload['issuer'], expected)


if __name__ == '__main__':
    unittest.main()
