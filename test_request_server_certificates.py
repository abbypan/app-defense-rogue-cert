#!/usr/bin/env python3
"""Offline certificate request tests; no ACME or GoDaddy requests are made."""
from contextlib import redirect_stdout, redirect_stderr
from datetime import datetime, timedelta, timezone
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

SPEC = importlib.util.spec_from_file_location("certificate_requests", Path(__file__).with_name("request-server-certificates.py"))
acme = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = acme
SPEC.loader.exec_module(acme)


class CertificateRequestsTest(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.directory = Path(self.temporary.name)
        self.root = self.directory/"repo"
        self.state = self.directory/"state"
        self.root.mkdir()
        self.state.mkdir(mode=0o700)
        self.key = ec.generate_private_key(ec.SECP256R1())
        self.ca_key = ec.generate_private_key(ec.SECP256R1())
        self.name = "service.example.invalid"
        now = datetime.now(timezone.utc)
        ca_name = x509.Name([x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Let's Encrypt"),
                             x509.NameAttribute(NameOID.COMMON_NAME, "Offline test CA")])
        self.ca = (x509.CertificateBuilder().subject_name(ca_name).issuer_name(ca_name)
                   .public_key(self.ca_key.public_key()).serial_number(x509.random_serial_number())
                   .not_valid_before(now-timedelta(days=1)).not_valid_after(now+timedelta(days=365))
                   .add_extension(x509.BasicConstraints(ca=True, path_length=None), True)
                   .sign(self.ca_key, hashes.SHA256()))
        self.ca_bundle = self.directory/"test-ca.pem"
        self.ca_bundle.write_bytes(self.ca.public_bytes(serialization.Encoding.PEM))
        self.folder = self.root/"realserver/etc/cert/es256"
        self.folder.mkdir(parents=True)
        subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, self.name)])
        self.csr = (x509.CertificateSigningRequestBuilder().subject_name(subject)
                    .add_extension(x509.SubjectAlternativeName([x509.DNSName(self.name)]), False)
                    .sign(self.key, hashes.SHA256()))
        (self.folder/"real-csr.pem").write_bytes(self.csr.public_bytes(serialization.Encoding.PEM))
        self.write_key(self.key)
        self.write_bundle(tuple(self.folder/name for name in (
            "real-cert.pem", "real-chain.pem", "real-fullchain.pem")))
        self.environment = {"GODADDY_TOKEN": "gd_pat_offline_fixture_not_a_real_token"}
        self.account = (self.state/"letsencrypt/config/accounts"/
                        "acme-v02.api.letsencrypt.org/directory/offline-account")
        self.account.mkdir(parents=True)
        for filename in ("regr.json", "meta.json", "private_key.json"):
            (self.account/filename).write_text("{}")

    def write_key(self, key):
        (self.folder/"real-privkey.pem").write_bytes(key.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))

    def leaf(self, days=90, hostname=None, key=None):
        now = datetime.now(timezone.utc)
        return (x509.CertificateBuilder().subject_name(self.csr.subject).issuer_name(self.ca.subject)
                .public_key((key or self.key).public_key()).serial_number(x509.random_serial_number())
                .not_valid_before(now-timedelta(days=1)).not_valid_after(now+timedelta(days=days))
                .add_extension(x509.SubjectAlternativeName([x509.DNSName(hostname or self.name)]), False)
                .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), False)
                .sign(self.ca_key, hashes.SHA256()))

    def write_bundle(self, paths, **kwargs):
        cert = self.leaf(**kwargs).public_bytes(serialization.Encoding.PEM)
        chain = self.ca.public_bytes(serialization.Encoding.PEM)
        for path, data in zip(paths, (cert, chain, cert+chain)):
            path.write_bytes(data)

    def jobs(self, refresh=False):
        return acme.prepare_jobs(self.root, "letsencrypt", ["es256"], refresh)

    def args(self, *extra):
        return acme.parser().parse_args(["--repo-root", str(self.root), "--state-dir", str(self.state),
            "--ca", "letsencrypt", "--targets", "es256", "--ca-bundle", str(self.ca_bundle), *extra])

    def test_valid_certificate_skipped_and_force_overrides(self):
        job = self.jobs()[0]
        self.assertFalse(acme.needs_renewal(job, self.args()))
        self.assertTrue(acme.needs_renewal(job, self.args("--force")))
        self.write_bundle(job.paths, days=5)
        self.assertTrue(acme.needs_renewal(job, self.args()))

    def test_existing_bad_certificate_is_not_silently_skipped(self):
        job = self.jobs()[0]
        self.write_bundle(job.paths, hostname="wrong.example.invalid")
        self.assertTrue(acme.needs_renewal(job, self.args()))

    def test_private_key_mismatch_rejected_before_request(self):
        self.write_key(ec.generate_private_key(ec.SECP256R1()))
        with self.assertRaisesRegex(ValueError, "CSR/private-key mismatch"):
            self.jobs()

    def test_duplicate_targets_rejected(self):
        with self.assertRaisesRegex(ValueError, "Duplicate"):
            acme.prepare_jobs(self.root, "letsencrypt", ["es256", "es256"], False)

    def test_default_plan_maps_all_nine_csrs_to_the_correct_ca(self):
        for ca, (server, prefix, _) in acme.PROVIDERS.items():
            for target in acme.TARGETS:
                if ca == "zerossl" and target == "dcp":
                    continue
                folder = self.root/server/"etc/cert"/target
                folder.mkdir(parents=True, exist_ok=True)
                (folder/f"{prefix}-csr.pem").write_bytes(self.csr.public_bytes(serialization.Encoding.PEM))
                (folder/f"{prefix}-privkey.pem").write_bytes(self.key.private_bytes(
                    serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
        jobs = acme.prepare_jobs(self.root, "all", None, False)
        self.assertEqual(len(jobs), 9)
        self.assertEqual(sum(job.provider == "letsencrypt" for job in jobs), 5)
        self.assertEqual(sum(job.provider == "zerossl" for job in jobs), 4)
        self.assertFalse(any(job.provider == "zerossl" and job.target == "dcp" for job in jobs))

    def test_refresh_preserves_private_key_subject_san_and_does_not_write_in_preflight(self):
        new_key = ec.generate_private_key(ec.SECP256R1())
        self.write_key(new_key)
        before = {p.name: p.read_bytes() for p in self.folder.iterdir()}
        job = self.jobs(refresh=True)[0]
        self.assertTrue(job.refresh)
        self.assertEqual(job.csr.subject, self.csr.subject)
        self.assertEqual(list(job.csr.extensions), list(self.csr.extensions))
        self.assertEqual(acme.public_der(job.csr.public_key()), acme.public_der(new_key.public_key()))
        self.assertEqual(before, {p.name:p.read_bytes() for p in self.folder.iterdir()})

    def test_validation_checks_key_hostname_fullchain_and_native_trust(self):
        job = self.jobs()[0]
        self.assertEqual(acme.verify_certificate(job, job.paths, self.ca_bundle).subject, self.csr.subject)
        self.write_bundle(job.paths, key=ec.generate_private_key(ec.SECP256R1()))
        with self.assertRaisesRegex(ValueError, "public-key mismatch"):
            acme.verify_certificate(job, job.paths, self.ca_bundle)
        self.write_bundle(job.paths, hostname="wrong.example.invalid")
        with self.assertRaisesRegex(ValueError, "SAN mismatch"):
            acme.verify_certificate(job, job.paths, self.ca_bundle)
        self.write_bundle(job.paths)
        job.paths[2].write_bytes(job.paths[0].read_bytes())
        with self.assertRaisesRegex(ValueError, "chain/fullchain"):
            acme.verify_certificate(job, job.paths, self.ca_bundle)

    def test_native_path_failure_cannot_pass_validation(self):
        with patch.object(acme.subprocess, "run", return_value=subprocess.CompletedProcess([], 1, "", "untrusted")):
            with self.assertRaisesRegex(ValueError, "Native certificate-path"):
                acme.verify_certificate(self.jobs()[0], self.jobs()[0].paths, self.ca_bundle)

    def test_missing_account_does_not_register(self):
        with self.assertRaisesRegex(ValueError, "No account will be registered"):
            acme.selected_account(self.state, "zerossl", None)
        self.assertEqual(acme.selected_account(self.state, "letsencrypt", None), "offline-account")
        with self.assertRaisesRegex(ValueError, "does not exist"):
            acme.selected_account(self.state, "letsencrypt", "wrong-account")

    def test_credential_permissions_and_environment_precedence(self):
        path = self.directory/"private.env"
        path.write_text("GODADDY_TOKEN=gd_pat_file_fixture\n")
        path.chmod(0o600)
        args = self.args("--env-file", str(path))
        with patch.dict(os.environ, self.environment, clear=True):
            self.assertEqual(acme.credential_environment(args)["GODADDY_TOKEN"], self.environment["GODADDY_TOKEN"])
            path.chmod(0o644)
            with self.assertRaisesRegex(ValueError, "Unsafe credential permissions"):
                acme.credential_environment(args)

    def test_all_configured_credentials_are_redacted(self):
        environment = {name: "fixture-secret-"+str(i) for i,name in enumerate(acme.SECRET_NAMES)}
        text = " ".join(environment.values())
        redacted = acme.Redactor(environment)(text)
        self.assertNotIn("fixture-secret", redacted)
        self.assertEqual(redacted.count("[REDACTED]"), len(environment))

    def test_lock_excludes_simultaneous_run(self):
        with acme.exclusive_run(self.state):
            with self.assertRaisesRegex(ValueError, "Another certificate"):
                with acme.exclusive_run(self.state):
                    self.fail("lock did not exclude second invocation")

    def test_explicit_virtualenv_python_symlink_is_not_resolved(self):
        python = self.directory/"venv/bin/python"
        python.parent.mkdir(parents=True)
        python.symlink_to(sys.executable)
        self.assertEqual(acme.certbot_python(python), str(python))

    def test_dry_run_force_never_invokes_certbot_or_writes(self):
        before = {str(p.relative_to(self.directory)):p.read_bytes()
                  for p in self.directory.rglob("*") if p.is_file()}
        with patch.dict(os.environ, self.environment), patch.object(acme, "run_certbot") as run:
            with redirect_stdout(io.StringIO()):
                result = acme.main(["--repo-root",str(self.root),"--state-dir",str(self.state),
                    "--ca","letsencrypt","--targets","es256","--force","--dry-run"])
        self.assertEqual(result, 0)
        run.assert_not_called()
        after = {str(p.relative_to(self.directory)):p.read_bytes()
                 for p in self.directory.rglob("*") if p.is_file()}
        self.assertEqual(before, after)

    def test_partial_install_failure_restores_every_original_file(self):
        paths = self.jobs()[0].paths
        before = {p:p.read_bytes() for p in paths}
        original = acme.atomic_write
        failed = False
        def write(path, data, mode=0o600):
            nonlocal failed
            if path == paths[1] and not failed:
                failed = True
                raise OSError("synthetic replacement failure")
            return original(path,data,mode)
        with patch.object(acme,"atomic_write",side_effect=write):
            with self.assertRaises(OSError):
                acme.install_files({p:b"replacement" for p in paths},self.state/"backup")
        self.assertEqual(before,{p:p.read_bytes() for p in paths})

    def fake_execute(self, invalid=False, refresh=False):
        args = self.args("--force", *(["--refresh-csr"] if refresh else []))
        original_run = subprocess.run
        observed = []
        def probe_or_openssl(command, **kwargs):
            if "-c" in command:
                return subprocess.CompletedProcess(command,0,"5.8.0\n3.0.1\n","")
            return original_run(command,**kwargs)
        def issue(python,command,environment,log_path,redact):
            observed.append(command)
            self.assertNotIn("--agree-tos",command)
            self.assertNotIn("--eab-hmac-key",command)
            self.assertEqual(command[command.index("--authenticator")+1],"dns-godaddy-v3")
            paths=tuple(Path(command[command.index(option)+1]) for option in (
                "--cert-path","--chain-path","--fullchain-path"))
            self.write_bundle(paths,hostname="wrong.example.invalid" if invalid else self.name)
        with patch.object(acme,"certbot_python",return_value=sys.executable), \
             patch.object(acme.subprocess,"run",side_effect=probe_or_openssl), \
             patch.object(acme,"run_certbot",side_effect=issue), redirect_stdout(io.StringIO()):
            acme.execute(args,self.environment,self.jobs(refresh),acme.Redactor(self.environment))
        return observed

    def test_successful_mock_issuance_installs_only_verified_public_files(self):
        key_before = (self.folder/"real-privkey.pem").read_bytes()
        old = {p.name:p.read_bytes() for p in self.jobs()[0].paths}
        self.assertEqual(len(self.fake_execute()),1)
        self.assertEqual(key_before,(self.folder/"real-privkey.pem").read_bytes())
        manifest = json.loads(next((self.state/"runs").glob("*/manifest.json")).read_text())
        self.assertEqual(manifest["status"],"complete")
        record=manifest["jobs"][0]
        self.assertEqual(record["status"],"verified_and_installed")
        self.assertEqual(old,{p.name:p.read_bytes() for p in Path(record["backup"]).iterdir()})
        self.assertFalse(list((self.state/"runs").glob("*/godaddy-v3.ini")))
        self.assertNotIn(self.environment["GODADDY_TOKEN"],json.dumps(manifest))

    def test_invalid_new_certificate_preserves_old_files_and_removes_credentials(self):
        before={p:p.read_bytes() for p in self.jobs()[0].paths}
        with self.assertRaisesRegex(ValueError,"SAN mismatch"):
            self.fake_execute(invalid=True)
        self.assertEqual(before,{p:p.read_bytes() for p in self.jobs()[0].paths})
        self.assertFalse(list((self.state/"runs").glob("*/godaddy-v3.ini")))
        manifest=json.loads(next((self.state/"runs").glob("*/manifest.json")).read_text())
        self.assertEqual(manifest["status"],"failed")

    def test_mock_issuance_with_csr_repair_backs_up_old_csr_and_preserves_key(self):
        old_csr = (self.folder/"real-csr.pem").read_bytes()
        self.key = ec.generate_private_key(ec.SECP256R1())
        self.write_key(self.key)
        key_before = (self.folder/"real-privkey.pem").read_bytes()
        self.fake_execute(refresh=True)
        manifest=json.loads(next((self.state/"runs").glob("*/manifest.json")).read_text())
        record=manifest["jobs"][0]
        self.assertTrue(record["csr_refreshed"])
        self.assertEqual((Path(record["backup"])/"real-csr.pem").read_bytes(),old_csr)
        self.assertEqual((self.folder/"real-privkey.pem").read_bytes(),key_before)
        self.assertFalse(self.jobs()[0].refresh)


if __name__ == "__main__":
    unittest.main()
