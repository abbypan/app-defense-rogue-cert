#!/usr/bin/env python3
"""Offline eligibility/oracle checks; these are not reported device evidence."""
from datetime import datetime, timedelta, timezone
import importlib.util
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

ROOT = Path(__file__).resolve().parent


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, ROOT / filename)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


prepare = load("certificate_change_test_fixtures", "prepare-certificate-change.py")
runner = load("certificate_change_test_runner", "run-certificate-change-benchmark.py")
summary = load("certificate_change_test_summary", "summarize-certificate-change-results.py")


class CertificateChangeTest(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.ca_key = ec.generate_private_key(ec.SECP256R1())
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Offline fixture issuer")])
        now = datetime.now(timezone.utc)
        self.ca = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
            .public_key(self.ca_key.public_key()).serial_number(1)
            .not_valid_before(now - timedelta(days=1)).not_valid_after(now + timedelta(days=3))
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), True)
            .sign(self.ca_key, hashes.SHA256()))
        self.old, self.new = [ec.generate_private_key(ec.SECP256R1()) for _ in range(2)]

    def leaf(self, folder, key, serial, ca=None, ca_key=None, host="service.example.invalid"):
        ca, ca_key = ca or self.ca, ca_key or self.ca_key
        now = datetime.now(timezone.utc)
        subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, host)])
        leaf = (x509.CertificateBuilder().subject_name(subject).issuer_name(ca.subject)
            .public_key(key.public_key()).serial_number(serial)
            .not_valid_before(now - timedelta(hours=1)).not_valid_after(now + timedelta(days=1))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName(host)]), False)
            .sign(ca_key, hashes.SHA256()))
        folder.mkdir(parents=True, exist_ok=True)
        encoded = leaf.public_bytes(serialization.Encoding.PEM)
        issuer = ca.public_bytes(serialization.Encoding.PEM)
        (folder / "leaf.pem").write_bytes(encoded)
        (folder / "chain.pem").write_bytes(issuer)
        (folder / "fullchain.pem").write_bytes(encoded + issuer)
        (folder / "tls-key.pem").write_bytes(key.private_bytes(serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
        return folder

    def complete(self):
        for phase, key, serial in (("real", self.old, 2), ("renewal", self.old, 3), ("rekey", self.new, 4)):
            self.leaf(self.root / phase, key, serial)

    def inspect(self, **kw):
        with patch.object(prepare.subprocess, "run", return_value=subprocess.CompletedProcess([], 0, "", "")):
            return prepare.inspect_fixtures(self.root, **kw)

    def test_distinct_leaves_same_ca_and_required_key_relationships(self):
        self.complete()
        records = self.inspect()
        self.assertEqual(records["real"]["spki_sha256"], records["renewal"]["spki_sha256"])
        self.assertNotEqual(records["real"]["spki_sha256"], records["rekey"]["spki_sha256"])
        self.assertEqual(len({r["issuer_der_sha256"] for r in records.values()}), 1)

    def test_public_audit_does_not_require_tls_private_keys(self):
        self.complete()
        for phase in prepare.PHASES: (self.root / phase / "tls-key.pem").unlink()
        self.assertEqual(len(self.inspect(require_private_keys=False)), 3)

    def test_key_replacement_is_not_same_key_renewal(self):
        self.complete()
        self.leaf(self.root / "renewal", self.new, 8)
        with self.assertRaisesRegex(ValueError, "Renewal must keep"):
            self.inspect()

    def test_unmodified_public_key_is_not_rekeying(self):
        self.complete()
        self.leaf(self.root / "rekey", self.old, 8)
        with self.assertRaisesRegex(ValueError, "Rekey must replace"):
            self.inspect()

    def test_existing_leaf_is_not_a_renewal(self):
        self.complete()
        for filename in ("leaf.pem", "chain.pem", "fullchain.pem"):
            shutil.copyfile(self.root / "real" / filename, self.root / "renewal" / filename)
        with self.assertRaisesRegex(ValueError, "distinct issued leaf"):
            self.inspect()

    def test_changed_hostname_is_not_eligible(self):
        self.complete()
        self.leaf(self.root / "rekey", self.new, 8, host="other.example.invalid")
        with self.assertRaisesRegex(ValueError, "same Subject/SAN"):
            self.inspect()

    def test_ca_der_change_cannot_be_hidden_by_equal_ca_names(self):
        self.complete()
        other = (x509.CertificateBuilder().subject_name(self.ca.subject).issuer_name(self.ca.issuer)
            .public_key(self.ca_key.public_key()).serial_number(123)
            .not_valid_before(self.ca.not_valid_before_utc).not_valid_after(self.ca.not_valid_after_utc)
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), True)
            .sign(self.ca_key, hashes.SHA256()))
        self.leaf(self.root / "rekey", self.new, 8, ca=other)
        with self.assertRaisesRegex(ValueError, "Direct issuer DER differs"):
            self.inspect()

    def test_native_trust_failure_is_not_a_success(self):
        self.complete()
        with patch.object(prepare.subprocess, "run", return_value=subprocess.CompletedProcess([], 1, "", "untrusted")):
            with self.assertRaisesRegex(ValueError, "Native public trust"):
                prepare.inspect_fixtures(self.root)

    def test_triplet_selection_is_based_on_ca_and_key_not_device_outcome(self):
        a = self.leaf(self.root / "first", self.old, 2)
        b = self.leaf(self.root / "renewed", self.old, 3)
        c = self.leaf(self.root / "changed", self.new, 4)
        chosen = prepare.select_triplet({"baseline": a, "renewal": b, "rekey": c})
        self.assertEqual(chosen, {"real": "baseline", "renewal": "renewal", "rekey": "rekey"})

    def test_no_same_key_pair_cannot_be_fabricated(self):
        a = self.leaf(self.root / "first", self.old, 2)
        b = self.leaf(self.root / "changed", self.new, 3)
        with self.assertRaisesRegex(ValueError, "No same-direct-issuer"):
            prepare.select_triplet({"a": a, "b": b})

    def test_plan_covers_all_five_configurations_and_both_changes(self):
        cells = runner.plan("offline")
        self.assertEqual(len(cells), 15)
        self.assertEqual(len({c["scenario"] for c in cells}), 15)
        self.assertEqual(sum(c["reuse_cached_policy"] for c in cells), 4)
        for cell in cells:
            actual = runner.comparison.expected_outcome(cell["scheme"], cell["phase"])
            expected = "policy_rejected" if cell["phase"] == "rekey" and cell["scheme"] in ("SCP", "DCP") else "accepted"
            self.assertEqual(actual, expected)

    def test_unknown_certificate_stage_is_not_accepted(self):
        with self.assertRaises(ValueError): runner.comparison.expected_outcome("ASPin", "invented")


class CertificateChangePaperTest(unittest.TestCase):
    def fixture(self):
        rows = []
        for cell in runner.plan("offline"):
            accepted = runner.comparison.expected_outcome(cell["scheme"], cell["phase"]) == "accepted"
            rows.append({"scheme": cell["scheme"], "phase": cell["phase"],
                         "accepted": 20 if accepted else 0, "attempts": 20})
        text = (r"\label{table:evaluation-certificate-change}" + "\n"
                "Baseline & 20/20 & 20/20 & 20/20 & 20/20 & 20/20\\\\\n"
                "Renewal & 20/20 & 20/20 & 20/20 & 20/20 & 20/20\\\\\n"
                "TLS rekey & 20/20 & 0/20 & 0/20 & 20/20 & 20/20\\\\\n"
                + r"\end{table}")
        return {"rows": rows}, text

    def test_paper_table_matches_audited_counts(self):
        results, text = self.fixture()
        summary.check_paper(results, text)

    def test_changed_paper_count_is_not_accepted(self):
        results, text = self.fixture()
        with self.assertRaisesRegex(ValueError, "differ from observations"):
            summary.check_paper(results, text.replace("& 0/20", "& 20/20", 1))

    def test_missing_paper_table_is_not_accepted(self):
        with self.assertRaisesRegex(ValueError, "Missing certificate-change"):
            summary.check_paper({"rows": []}, "")


if __name__ == "__main__":
    unittest.main()
