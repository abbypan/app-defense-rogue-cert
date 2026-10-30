#!/usr/bin/env python3
"""Offline controls for public issuance and experiment protocol. No network/ADB."""
import importlib.util
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch
import xml.etree.ElementTree as ET

from cryptography import x509
from cryptography.hazmat.primitives import serialization

import public_cross_protocol as protocol

ROOT = Path(__file__).resolve().parent


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, ROOT / filename)
    module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
    return module


REQUEST = load("public_request_test", "request-public-cross-certificates.py")
RUNNER = load("public_runner_test", "run-public-cross-benchmark.py")


class PublicCrossTest(unittest.TestCase):
    def test_single_csr_is_reused_without_regenerating_key(self):
        with tempfile.TemporaryDirectory() as temp:
            directory = Path(temp)
            key, csr = REQUEST.prepare_csr(directory, "test.example")
            before = key.read_bytes(), csr.read_bytes()
            self.assertEqual((key, csr), REQUEST.prepare_csr(directory, "test.example"))
            self.assertEqual(before, (key.read_bytes(), csr.read_bytes()))
            jobs = REQUEST.ACME.prepare_shared_csr_jobs(csr, key, directory / "certs", "all")
            self.assertEqual(len(jobs), 2)
            self.assertEqual({j.csr_path for j in jobs}, {csr})
            self.assertEqual({j.key_path for j in jobs}, {key})
            self.assertEqual(len({j.csr_hash for j in jobs}), 1)
            self.assertEqual(key.stat().st_mode & 0o777, 0o600)

    def test_existing_key_or_csr_is_not_overwritten(self):
        with tempfile.TemporaryDirectory() as temp:
            directory = Path(temp)
            (directory / "server-privkey.pem").write_text("existing material")
            with self.assertRaises(ValueError): REQUEST.prepare_csr(directory, "test.example")
            self.assertEqual((directory / "server-privkey.pem").read_text(), "existing material")

    def test_configuring_a_never_overwrites_conflicting_records(self):
        with tempfile.TemporaryDirectory() as temp:
            for conflicts in ([[], [{"data": "::1"}], []], [[], [], [{"data": "other.example"}]],
                              [[{"data": "192.0.2.9"}], [], []]):
                session = Mock()
                with patch.object(REQUEST.requests, "Session", return_value=session), \
                        patch.object(REQUEST, "dns_records", side_effect=conflicts), self.assertRaises(ValueError):
                    REQUEST.configure_a({"GODADDY_TOKEN": "offline-not-a-secret"}, "example", "test.example",
                                        "192.0.2.1", Path(temp), True)
                session.post.assert_not_called()

    def test_public_apks_use_only_system_roots(self):
        RUNNER.system_roots_only()
        tree = ET.parse(ROOT / "ASPin/shared/src/main/res/xml/network_security_public_cross.xml")
        self.assertEqual([n.get("src") for n in tree.findall(".//certificates")], ["system"])

    def test_one_additional_sni_route_preserves_other_configuration(self):
        before = "frontend shared_tls\n    default_backend previous_tls\nbackend previous_tls\n    server original 127.0.0.1:10443\n"
        after = RUNNER.sni_config(before, "test.example")
        self.assertIn("    default_backend previous_tls\n", after)
        self.assertIn("    server original 127.0.0.1:10443\n", after)
        self.assertIn("req_ssl_sni -i test.example", after)
        with self.assertRaises(ValueError): RUNNER.sni_config(after, "test.example")
        with self.assertRaises(ValueError): RUNNER.sni_config(before, "test.example; invalid")

    def test_protocol_covers_both_public_issuers_and_cross_chain_presentations(self):
        cells = protocol.plan()
        self.assertEqual(len(cells), 9)
        self.assertEqual(sum(c[3] for c in cells), 5)
        self.assertEqual(len({c[0] for c in cells}), 9)
        self.assertIn(("le-only-zerossl", "zerossl", "le-only", False, False), cells)
        self.assertIn(("zerossl-only-le", "le", "zerossl-only", False, False), cells)
        self.assertIn(("ancestor-only-le", "le", "ancestor-only", False, False), cells)
        self.assertTrue(any(c[1] == "le-short" and c[3] for c in cells))

    def test_unattributed_public_requests_are_kept_but_not_misattributed(self):
        outsider = {"path": "/", "generation": "case", "observation": "", "status": 200}
        measured = {"path": "/", "generation": "case", "observation": "case-0", "status": 200}
        audit = RUNNER.audit_public_requests([outsider, measured], "case", 1, True)
        self.assertEqual(audit, {"tagged": [measured], "unattributed": [outsider]})
        self.assertEqual(RUNNER.audit_public_requests([outsider], "case", 1, False)["unattributed"], [outsider])
        for items in ([measured, measured], [measured | {"observation": "wrong"}], []):
            with self.subTest(items=items), self.assertRaises(ValueError):
                RUNNER.audit_public_requests(items, "case", 1, True)


if __name__ == "__main__": unittest.main()
