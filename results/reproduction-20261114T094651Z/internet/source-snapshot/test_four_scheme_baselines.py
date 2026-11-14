#!/usr/bin/env python3
"""Offline tests of the CURRENT AOSP DCP verification source and APK separation.

Only Android runtime wrappers (Base64/Build/properties) and desktop PSS provider
names are adapted. These tests are not Pixel measurements or a TLS-path test.
"""
import base64
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
import xml.etree.ElementTree as ET

from cryptography.hazmat.primitives import serialization

ROOT = Path(__file__).resolve().parent
AOSP = Path(os.environ.get("ASPIN_AOSP_ROOT", "/mnt/code/aosp-main/aosp"))
SPEC = importlib.util.spec_from_file_location("dcp_generator", ROOT / "signing/gen_dcp_policy.py")
GEN = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(GEN)


class IndependentDcpSourceTest(unittest.TestCase):
    SOURCE = "external/conscrypt/nsc/src/android/security/net/config/DcpPinningVerifier.java"
    @classmethod
    def setUpClass(cls):
        if not shutil.which("javac"):
            raise unittest.SkipTest("javac is required")
        temporary = tempfile.TemporaryDirectory()
        cls.addClassCleanup(temporary.cleanup)
        cls.root = Path(temporary.name)
        cls.jar = AOSP / "prebuilts/misc/common/json/json-prebuilt.jar"
        source = AOSP / cls.SOURCE
        code = source.read_text()
        # The Android provider exposes digest-specific aliases; the desktop JDK
        # uses RSASSA-PSS with the same explicit hash/MGF1/salt parameters.
        code = code.replace('Signature.getInstance(sha256 ? "SHA256withRSA/PSS" : "SHA384withRSA/PSS")',
                            'Signature.getInstance("RSASSA-PSS")')
        files = {
            "android/security/net/config/DcpPinningVerifier.java": code,
            "android/os/Build.java": "package android.os; public class Build { public static final boolean IS_DEBUGGABLE=false; public static boolean isDebuggable() { return false; } }",
            "android/os/SystemProperties.java": "package android.os; public class SystemProperties { public static boolean getBoolean(String k, boolean d) { return d; } }",
            "android/util/Base64.java": """package android.util;
public class Base64 {
 public static final int URL_SAFE=8, NO_WRAP=2, NO_PADDING=1, DEFAULT=0;
 public static byte[] decode(String s,int flags) { return (flags==0 ? java.util.Base64.getDecoder() : java.util.Base64.getUrlDecoder()).decode(s); }
 public static String encodeToString(byte[] s,int flags) { return java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(s); }
} """,
            "android/security/net/config/DcpHostTest.java": """package android.security.net.config;
import java.nio.file.*;
import java.lang.reflect.*;
public class DcpHostTest {
 public static void main(String[] args) throws Exception {
  var root=DcpPinningVerifier.parsePublicKey(Files.readString(Path.of(args[0])));
  var verifier=new DcpPinningVerifier(root,null);
  var verify=DcpPinningVerifier.class.getDeclaredMethod("verify",String.class,String.class);
  verify.setAccessible(true);
  verify.invoke(verifier,Files.readString(Path.of(args[1])),args[2]);
  System.out.println("PASS");
 }
} """,
        }
        paths = []
        for name, value in files.items():
            target = cls.root / name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(value)
            paths.append(str(target))
        result = subprocess.run(["javac", "-cp", str(cls.jar), *paths], capture_output=True, text=True)
        if result.returncode:
            raise AssertionError(result.stderr)

    def verify(self, variant, token, host=None, root_variant=None):
        source = ROOT / "signing" / (root_variant or variant) / "my-dcp-pubkey.pem"
        key = serialization.load_pem_public_key(source.read_bytes())
        public = self.root / "root.txt"
        public.write_text(base64.b64encode(key.public_bytes(serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo)).decode())
        value = self.root / "policy.jws"
        value.write_text(token)
        return subprocess.run(["java", "-cp", str(self.root) + os.pathsep + str(self.jar),
            "android.security.net.config.DcpHostTest", str(public), str(value),
            host or variant + ".idouzi.top"], capture_output=True, text=True)

    def test_all_four_signature_profiles(self):
        for variant in GEN.ALGORITHMS:
            with self.subTest(variant=variant):
                result = self.verify(variant, GEN.generate(ROOT, variant))
                self.assertEqual(result.returncode, 0, result.stderr)

    def test_hostname_and_manifest_root_substitution_rejected(self):
        token = GEN.generate(ROOT, "es256")
        self.assertNotEqual(self.verify("es256", token, "unrelated.example").returncode, 0)
        self.assertNotEqual(self.verify("es256", token, root_variant="es384").returncode, 0)

    def test_signed_expiry_and_future_issuance(self):
        for now in (1, 4102444800):
            self.assertNotEqual(self.verify("es256", GEN.generate(ROOT, "es256", now=now, lifetime=1)).returncode, 0)

    def test_payload_splicing_and_unsigned_metadata_rejected(self):
        value = json.loads(GEN.generate(ROOT, "es256"))
        value["payload"] = GEN.b64(b'{"hostname":"es256.idouzi.top","pins":[],"iat":1,"exp":9999999999}')
        self.assertNotEqual(self.verify("es256", json.dumps(value)).returncode, 0)
        value["signatures"] = []
        self.assertNotEqual(self.verify("es256", json.dumps(value)).returncode, 0)


class PlatformDcpSourceTest(IndependentDcpSourceTest):
    SOURCE = "frameworks/base/packages/NetworkSecurityConfig/platform/src/android/security/net/config/DcpPinningVerifier.java"


class ConfigurationSeparationTest(unittest.TestCase):
    def test_four_apks_do_not_conflate_dcp_and_aspin_compatibility(self):
        for variant in GEN.ALGORITHMS:
            root = ROOT / "ASPin" / variant / "app"
            dcp = (root / "src/dcpBenchmark/AndroidManifest.xml").read_text()
            compatible = (root / "src/compatibilityBenchmark/AndroidManifest.xml").read_text()
            self.assertIn("android.security.dcp.POLICY_PUBLIC_KEY", dcp)
            self.assertNotIn("android.security.aspin.POLICY_PUBLIC_KEY", dcp)
            self.assertIn("android.security.aspin.POLICY_PUBLIC_KEY", compatible)
            self.assertNotIn("android.security.dcp.POLICY_PUBLIC_KEY", compatible)
            self.assertNotIn("dynamic-pin-set", (root / "src/compatibilityBenchmark/res/xml/network_security_config.xml").read_text())

    def test_nsc_dcp_never_calls_aspin(self):
        directory = AOSP / "frameworks/base/packages/NetworkSecurityConfig/platform/src/android/security/net/config"
        for name in ("DcpPinningVerifier.java", "NetworkSecurityTrustManager.java"):
            code = (directory / name).read_text()
            self.assertNotIn("IAspinService", code)
            self.assertNotIn("getOwnCertificateClaim", code)
        self.assertIn("DCPServerCertPin.jws", (directory / "DcpPinningVerifier.java").read_text())

    def test_active_conscrypt_nsc_has_the_same_independent_verifier(self):
        active = AOSP / "external/conscrypt/nsc/src/android/security/net/config"
        platform = AOSP / "frameworks/base/packages/NetworkSecurityConfig/platform/src/android/security/net/config"
        self.assertEqual((active / "DcpPinningVerifier.java").read_text(),
                         (platform / "DcpPinningVerifier.java").read_text().replace("Build.IS_DEBUGGABLE", "Build.isDebuggable()"))
        self.assertIn("android.security.dcp.POLICY_PUBLIC_KEY", (active / "XmlConfigSource.java").read_text())
        self.assertIn("new DcpPinningVerifier", (active / "NetworkSecurityTrustManager.java").read_text())
        self.assertNotIn("IAspinService", (active / "NetworkSecurityTrustManager.java").read_text())


class CurrentSchemeSourcesTest(unittest.TestCase):
    def test_only_current_runtime_classes_and_dependencies_remain(self):
        expected = {"ASPinVerifier.java", "AppTrustedServerCert.java", "HttpsConn.java",
                    "MainActivity.java", "OsAspinClient.java"}
        for variant in GEN.ALGORITHMS:
            with self.subTest(variant=variant):
                app = ROOT / "ASPin" / variant / "app"
                java = app / "src/main/java/com/cert/aspin"
                self.assertEqual({source.name for source in java.glob("*.java")}, expected)
                self.assertEqual(list((app / "src/main/resources").glob("*")), [])
                gradle = (app / "build.gradle").read_text()
                for old_dependency in ("nimbus-jose-jwt", "bcprov-jdk18on", "kerby-asn1"):
                    self.assertNotIn(old_dependency, gradle)
                # CertClaimCheck still needs strict literal-IP normalization.
                self.assertIn("com.google.guava:guava", gradle)

    def test_old_manual_dcp_artifacts_and_generators_are_absent(self):
        for variant in GEN.ALGORITHMS:
            with self.subTest(variant=variant):
                signing = ROOT / "signing" / variant
                self.assertFalse((signing / "gen_dcp.py").exists())
                self.assertFalse((signing / "DCPServerCertPin.json").exists())
                self.assertFalse((ROOT / "realserver/var/www/dcp/.well-known"
                                  / ("DCPServerCertPin-" + variant + ".json")).exists())
                self.assertTrue((ROOT / "realserver/var/www" / variant
                                 / ".well-known/DCPServerCertPin.jws").is_file())

    def test_independent_nsc_configuration_and_manifest_roots_are_preserved(self):
        android = "{http://schemas.android.com/apk/res/android}"
        for variant in GEN.ALGORITHMS:
            with self.subTest(variant=variant):
                app = ROOT / "ASPin" / variant / "app"
                manifest = ET.parse(app / "src/dcpBenchmark/AndroidManifest.xml")
                application = manifest.find("application")
                self.assertEqual(application.get(android + "networkSecurityConfig"),
                                 "@xml/network_security_config")
                entries = application.findall("meta-data")
                self.assertEqual([entry.get(android + "name") for entry in entries],
                                 ["android.security.dcp.POLICY_PUBLIC_KEY"])
                self.assertEqual(entries[0].get(android + "value"), "${dcpPolicyPublicKey}")
                config = ET.parse(app / "src/dcpBenchmark/res/xml/network_security_config.xml")
                self.assertEqual(len(config.findall(".//dynamic-pin-set")), 1)
                self.assertEqual(config.findall(".//pin-set"), [])
                signing = ROOT / "signing" / variant
                key = serialization.load_pem_public_key((signing / "my-dcp-pubkey.pem").read_bytes())
                der = key.public_bytes(serialization.Encoding.DER,
                                       serialization.PublicFormat.SubjectPublicKeyInfo)
                encoded = (signing / "my-dcp-pub.txt").read_text().strip()
                try:
                    decoded = bytes.fromhex(encoded)
                except ValueError:
                    decoded = base64.b64decode(encoded, validate=True)
                self.assertEqual(decoded, der)
                self.assertTrue((signing / "my-dcp-key.pem").is_file())
                key_script = (signing / "gen_dcp_signing_key.sh").read_text()
                self.assertIn("openssl pkey -pubin", key_script)
                self.assertIn("my-dcp-pub.txt", key_script)

    def test_no_manual_pinning_or_tls_bypass_path_is_left_in_apps(self):
        obsolete = ("DCPVerifier", "SCPVerifier", "createDCPConnection", "createSCPConnection",
                    "create_main_conn", "BenchmarkVerifier", "JwsVerifier", "PemUtils",
                    "getBypassTrustManagers", "createBypassSslSocketFactory",
                    "setHostnameVerifier", "DCPServerCertPin-")
        for variant in GEN.ALGORITHMS:
            with self.subTest(variant=variant):
                directory = ROOT / "ASPin" / variant / "app/src/main/java/com/cert/aspin"
                for source in directory.glob("*.java"):
                    for name in obsolete:
                        self.assertNotIn(name, source.read_text(), str(source))
                main = (directory / "MainActivity.java").read_text()
                for mode in ("avgveriftime", "avgvisittime", "schemecomparison", "rttcache",
                             "policyscenario", "crosssign", "concurrency", "claimprobe",
                             "parallelrefresh", "expirybound"):
                    self.assertIn('"' + mode + '"', main)
                self.assertIn("connectWithASPin()", main)
                https = (directory / "HttpsConn.java").read_text()
                check = https.split("public static HttpsURLConnection createASPinConnection", 1)[1]
                self.assertLess(check.index("authenticatedClaim == null"),
                                check.index("resolveHost(host)"))

    def test_generation_and_local_diagnostics_do_not_reintroduce_app_policy_resources(self):
        generator = (ROOT / "gen-trust-artifacts.py").read_text()
        self.assertNotIn("app_resources_dir", generator)
        self.assertIn("gen_dcp_policy.py", generator)
        self.assertIn("write_nsc_experiment_configs(repo_root, alg, scp_pin)", generator)
        self.assertNotIn("app/src/main/resources", (ROOT / "run-robustness-benchmark.sh").read_text())


if __name__ == "__main__":
    unittest.main()
