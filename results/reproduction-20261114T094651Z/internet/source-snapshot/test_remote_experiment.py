#!/usr/bin/env python3
"""Offline origin/deployment checks; never modifies a device or remote host."""

import http.client
import importlib.util
import json
from pathlib import Path
import socket
import ssl
import tempfile
import threading
import unittest


ROOT = Path(__file__).resolve().parent


def module(name, filename):
    spec = importlib.util.spec_from_file_location(name, ROOT / filename)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


origin_module = module("remote_origin", "remote-experiment/server.py")
deploy = module("remote_deploy", "deploy-remote-experiment.py")


class RemoteOriginTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory()
        cls.addClassCleanup(cls.temporary.cleanup)
        cls.root = Path(cls.temporary.name)
        cls.manifest = deploy.prepare(cls.root)
        cls.host = next(name for name, entry in cls.manifest["hosts"].items()
                        if entry["algorithm"] == "es256")
        cls.origin = origin_module.Origin(cls.root / "manifest.json", cls.root / "state.json")
        cls.server = origin_module.ExperimentServer(("127.0.0.1", 0), origin_module.Handler)
        cls.server.origin = cls.origin
        cls.server.tls = cls.origin.tls_context()
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.addClassCleanup(cls.server.server_close)
        cls.addClassCleanup(cls.server.shutdown)

    def setUp(self):
        self.set_state()

    def set_state(self, **values):
        (self.root / "state.json").write_text(json.dumps({"default": values, "hosts": {}}))

    def connect(self):
        raw = socket.create_connection(self.server.server_address, timeout=5)
        return ssl.create_default_context().wrap_socket(raw, server_hostname=self.host)

    def request(self, path, host=None, connection=None):
        with connection or self.connect() as connection:
            connection.sendall(("GET " + path + " HTTP/1.1\r\nHost: "
                + (host or self.host) + "\r\nConnection: close\r\n\r\n").encode())
            response = http.client.HTTPResponse(connection)
            response.begin()
            return response.status, response.read()

    def test_public_ca_native_tls_accepts_both_certificate_phases(self):
        leaves = []
        for phase in ("real", "rogue"):
            self.set_state(phase=phase)
            with self.connect() as connection:
                leaves.append(connection.getpeercert(binary_form=True))
            self.assertEqual(self.request("/")[0], 200)
        self.assertNotEqual(*leaves)

    def test_single_and_multi_owner_token_selection(self):
        for mode in ("primary", "compat"):
            for shared in (False, True):
                self.set_state(mode=mode, key_file="ClaimSigningKey."
                    + ("shared." if shared else "") + mode + ".jws")
                status, body = self.request("/.well-known/ClaimSigningKey.jws")
                self.assertEqual(status, 200)
                self.assertEqual(len(json.loads(body)["signatures"]), 4 if shared else 1)

    def test_metadata_suppression_does_not_break_native_business_path(self):
        self.set_state(metadata_fault="503")
        self.assertEqual(self.request("/.well-known/ServerCertClaim.jws")[0], 503)
        self.assertEqual(self.request("/")[0], 200)

    def test_independent_dcp_endpoint_is_not_an_aspin_delegation(self):
        status, body = self.request("/.well-known/DCPServerCertPin.jws")
        self.assertEqual(status, 200)
        token = json.loads(body)
        import base64
        payload = json.loads(base64.urlsafe_b64decode(token["payload"] + "=" * (-len(token["payload"]) % 4)))
        self.assertEqual(set(payload), {"hostname", "pins", "iat", "exp"})
        self.assertNotIn("cnf", payload)
        self.assertNotIn("issuer", payload)
        self.set_state(metadata_fault="503")
        self.assertEqual(self.request("/.well-known/DCPServerCertPin.jws")[0], 503)

    def test_connection_pins_state_at_handshake(self):
        connection = self.connect()
        self.set_state(metadata_fault="503", phase="rogue")
        self.assertEqual(self.request("/.well-known/ServerCertClaim.jws", connection=connection)[0], 200)
        self.assertEqual(self.request("/.well-known/ServerCertClaim.jws")[0], 503)

    def test_incomplete_handshake_does_not_block_policy_connection(self):
        with socket.create_connection(self.server.server_address, timeout=5):
            self.assertEqual(self.request("/.well-known/DCPServerCertPin.jws")[0], 200)

    def test_no_private_files_or_directory_listing(self):
        for path in ("/certificates/es256/real/tls-key.pem", "/manifest.json", "/state.json", "/../tls-key.pem"):
            self.assertEqual(self.request(path)[0], 404)

    def test_http_authority_must_match_tls_sni(self):
        self.assertEqual(self.request("/", host="unrelated.example")[0], 421)

    def test_artifact_path_and_state_validation(self):
        with self.assertRaises(ValueError):
            origin_module.safe_file(self.root, "../outside")
        self.set_state(key_file="../private.jws")
        with self.assertRaises(ValueError):
            origin_module.load_state(self.root / "state.json", self.host)

    def test_bundle_contains_no_app_claim_or_manifest_root_private_keys(self):
        private_files = [item for item in self.root.rglob("*") if item.is_file()
                         and b"PRIVATE KEY" in item.read_bytes()]
        self.assertEqual(len(private_files), 9)
        self.assertTrue(all(item.name == "tls-key.pem" for item in private_files))
        self.assertTrue(all(item.stat().st_mode & 0o077 == 0 for item in private_files))


if __name__ == "__main__":
    unittest.main()
