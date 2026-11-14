#!/usr/bin/env python3
"""Offline regression checks for the sole, Android-NSC SCP baseline."""

import base64
import hashlib
import importlib.util
from pathlib import Path
import unittest
import xml.etree.ElementTree as ET

from cryptography import x509
from cryptography.hazmat.primitives import serialization

ROOT = Path(__file__).resolve().parent
VARIANTS = ("es256", "es384", "rsa3072", "rsa4096")
ANDROID = "{http://schemas.android.com/apk/res/android}"
SPEC = importlib.util.spec_from_file_location("nsc_pin_generator", ROOT / "signing/gen_scp_hash.py")
GENERATOR = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(GENERATOR)


class NscOnlyScpTest(unittest.TestCase):
    def test_manual_scp_sources_and_packaged_hash_resources_are_gone(self):
        forbidden = ("SCPVerifier", "createSCPConnection", "getSCPTrustManagers",
                     "createSCPSSLSocketFactory", "benchmarkHttpsSCPConnection",
                     "runHttpsSCPConnectionBenchmark", "runTableAvgVisitTimeBenchmark")
        for variant in VARIANTS:
            with self.subTest(variant=variant):
                main = ROOT / "ASPin" / variant / "app/src/main"
                java = main / "java/com/cert/aspin"
                self.assertFalse((java / "SCPVerifier.java").exists())
                self.assertFalse((main / "resources/my-app-cert-scp-hash.txt").exists())
                for source in java.glob("*.java"):
                    for name in forbidden:
                        self.assertNotIn(name, source.read_text(), str(source))
                layout = ET.parse(main / "res/layout/activity_main.xml")
                ids = {entry.get(ANDROID + "id") for entry in layout.iter()}
                self.assertNotIn("@+id/httpsSCPConnectionBenchmarkButton", ids)
                self.assertNotIn("@+id/AvgVisitTimeBenchmarkButton", ids)

    def test_scp_manifests_select_nsc_without_dynamic_policy_roots(self):
        for variant in VARIANTS:
            with self.subTest(variant=variant):
                directory = ROOT / "ASPin" / variant / "app/src/scpBenchmark"
                application = ET.parse(directory / "AndroidManifest.xml").find("application")
                self.assertEqual(application.get(ANDROID + "networkSecurityConfig"),
                                 "@xml/network_security_config")
                self.assertEqual(application.findall("meta-data"), [])
                config = ET.parse(directory / "res/xml/network_security_config.xml")
                self.assertEqual(config.findall(".//dynamic-pin-set"), [])
                self.assertEqual(config.findall(".//debug-overrides"), [])
                for anchor in config.findall(".//certificates"):
                    self.assertNotEqual(anchor.get("overridePins"), "true")

    def test_nsc_pins_hash_spki_not_whole_certificate_der(self):
        for variant in VARIANTS:
            with self.subTest(variant=variant):
                leaf = ROOT / "realserver/etc/cert" / variant / "real-cert.pem"
                certificate = x509.load_pem_x509_certificate(leaf.read_bytes())
                spki = certificate.public_key().public_bytes(
                    serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
                expected = base64.b64encode(hashlib.sha256(spki).digest()).decode("ascii")
                config = ET.parse(ROOT / "ASPin" / variant / "app/src/scpBenchmark"
                                  / "res/xml/network_security_config.xml")
                domains = [entry.text for entry in config.findall(".//domain")]
                self.assertIn(variant + ".idouzi.top", domains)
                pin_sets = config.findall(".//pin-set")
                self.assertEqual(len(pin_sets), 1)
                self.assertNotIn("expiration", pin_sets[0].attrib)
                pins = pin_sets[0].findall("pin")
                self.assertEqual(len(pins), 1)
                self.assertEqual(pins[0].get("digest"), "SHA-256")
                self.assertEqual(pins[0].text.strip(), expected)
                self.assertEqual(GENERATOR.certificate_spki_sha256_base64(leaf), expected)
                self.assertEqual((ROOT / "signing" / variant
                                  / "my-app-cert-scp-hash.txt").read_text().strip(), expected)
                whole_certificate = base64.b64encode(hashlib.sha256(
                    certificate.public_bytes(serialization.Encoding.DER)).digest()).decode("ascii")
                self.assertNotEqual(expected, whole_certificate)

    def test_native_connections_have_no_legacy_scheme_dispatcher(self):
        for variant in VARIANTS:
            with self.subTest(variant=variant):
                source = (ROOT / "ASPin" / variant
                          / "app/src/main/java/com/cert/aspin/HttpsConn.java").read_text()
                self.assertNotIn("create_main_conn", source)
                self.assertIn("createStandardTLSConnection(String host)", source)
                self.assertNotIn("createBypassSslSocketFactory", source)
                self.assertIn("trustManagerFactory.init((KeyStore) null)", source)

    def test_comparison_runners_keep_nsc_path_and_apk_mode_guard(self):
        directory = ROOT / "ASPin/shared/src/main/java/com/cert/aspin"
        for name in ("SchemeComparisonBenchmark.java", "RttCacheBenchmark.java"):
            with self.subTest(runner=name):
                source = (directory / name).read_text()
                self.assertIn("BuildConfig.BENCHMARK_MODE", source)
                self.assertIn("Wrong", source)
                self.assertIn(": HttpsConn.createStandardTLSConnection(host)", source)
                self.assertNotIn("SCPVerifier", source)
        build = (ROOT / "gen-signed-apks.py").read_text()
        self.assertIn('"scp": ("scpBenchmark", "-scp")', build)
        for variant in VARIANTS:
            self.assertIn('buildConfigField "String", "BENCHMARK_MODE", \'"scp"\'',
                          (ROOT / "ASPin" / variant / "app/build.gradle").read_text())


if __name__ == "__main__":
    unittest.main()
