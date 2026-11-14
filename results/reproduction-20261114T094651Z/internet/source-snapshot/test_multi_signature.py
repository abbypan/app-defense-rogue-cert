#!/usr/bin/env python3
"""Host-only multi-owner JWS regressions; no image build or device measurements."""

import base64
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from jwcrypto import jwk, jws

ROOT = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("cosign_tk",
    ROOT / "signing" / "cosign_claim_signing_key.py")
cosigner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(cosigner)


def write_key(directory, name, key):
    private = directory / (name + ".key")
    public = directory / (name + ".pem")
    private.write_bytes(key.private_bytes(serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    private.chmod(0o600)
    public.write_bytes(key.public_key().public_bytes(serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo))
    return private, public


def seed_token(private):
    key = jwk.JWK.from_pem(private.read_bytes())
    public_der = serialization.load_pem_private_key(private.read_bytes(), None).public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    payload = {"cnf": {"jwk": json.loads(key.export_public())}, "iat": 100, "exp": 200}
    token = jws.JWS(json.dumps(payload).encode())
    token.add_signature(key, None, json.dumps({"alg": "ES256",
        "kid": cosigner.b64url(hashlib.sha256(public_der).digest())}), None)
    flattened = json.loads(token.serialize(compact=False))
    return json.dumps({"payload": flattened["payload"], "signatures": [
        {name: flattened[name] for name in ("protected", "signature")}]})


class MultiSignatureGenerationTest(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.initial = write_key(self.root, "owner-a", ec.generate_private_key(ec.SECP256R1()))
        self.token = seed_token(self.initial[0])

    def test_three_or_more_owners_preserve_payload_and_existing_signatures(self):
        signers = []
        for index in range(5):
            private, public = write_key(self.root, str(index), ec.generate_private_key(ec.SECP256R1()))
            signers.append(("ES256", private, public))
        result = cosigner.cosign(self.token, signers)
        value, original = json.loads(result), json.loads(self.token)
        self.assertEqual(len(value["signatures"]), 6)
        self.assertEqual(value["payload"], original["payload"])
        self.assertEqual(value["signatures"][:1], original["signatures"])
        for _, private, public in [("ES256", *self.initial), *signers]:
            verifier = jws.JWS()
            verifier.deserialize(result)
            verifier.verify(jwk.JWK.from_pem(public.read_bytes()))
            self.assertNotIn(private.read_text(), result)

    def test_mixed_algorithms_and_protected_kids(self):
        signers = []
        for alg, key in (("ES384", ec.generate_private_key(ec.SECP384R1())),
                         ("PS256", rsa.generate_private_key(65537, 2048)),
                         ("PS384", rsa.generate_private_key(65537, 2048))):
            signers.append((alg, *write_key(self.root, alg, key)))
        result = cosigner.cosign(self.token, signers)
        entries = json.loads(result)["signatures"][1:]
        for entry, (alg, _, public) in zip(entries, signers):
            verifier = jws.JWS()
            verifier.deserialize(result)
            verifier.verify(jwk.JWK.from_pem(public.read_bytes()))
            header = json.loads(base64.urlsafe_b64decode(entry["protected"] + "=" * (-len(entry["protected"]) % 4)))
            self.assertEqual(header["alg"], alg)
            self.assertEqual(set(header), {"alg", "kid"})

    def test_rejects_mismatched_key_pair_and_algorithm(self):
        other = write_key(self.root, "other", ec.generate_private_key(ec.SECP256R1()))
        for signer in (("ES256", self.initial[0], other[1]),
                       ("ES384", *self.initial), ("PS256", *self.initial)):
            with self.subTest(algorithm=signer[0]), self.assertRaises(ValueError):
                cosigner.cosign(self.token, [signer])

    def test_rejects_empty_signature_array_and_noncanonical_payload(self):
        value = json.loads(self.token)
        with self.assertRaises(ValueError):
            cosigner.cosign(json.dumps(dict(value, signatures=[])), [])
        with self.assertRaises(ValueError):
            cosigner.cosign(json.dumps(dict(value, payload=value["payload"] + "=")), [])

    def test_repeatable_cli_writes_only_general_jws(self):
        source, output = self.root / "tk.jws", self.root / "shared.jws"
        source.write_text(self.token)
        command = [sys.executable, str(ROOT / "signing" / "cosign_claim_signing_key.py"),
                   str(source)]
        for index in range(3):
            private, public = write_key(self.root, str(index), ec.generate_private_key(ec.SECP256R1()))
            command.extend(["--signer", "ES256", str(private), str(public)])
        command.extend(["--output", str(output)])
        result = subprocess.run(command, capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(len(json.loads(output.read_text())["signatures"]), 4)
        self.assertEqual(source.read_text(), self.token)


class AospMultiSignatureVerificationTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        aosp = Path(os.environ.get("ASPIN_AOSP_ROOT", "/mnt/code/aosp-main/aosp"))
        service = aosp / "frameworks/base/services/core/java/com/android/server/aspin/AspinService.java"
        cls.json_jar = aosp / "prebuilts/misc/common/json/json-prebuilt.jar"
        if not service.is_file() or not cls.json_jar.is_file() or not shutil.which("javac"):
            raise unittest.SkipTest("AOSP source, JSON library, and javac are required for source-method tests")
        cls.temporary = tempfile.TemporaryDirectory()
        cls.addClassCleanup(cls.temporary.cleanup)
        cls.root = Path(cls.temporary.name)
        source = service.read_text()
        methods = source[source.index("    private static VerifiedJws verifyJws("):
                         source.index("    private static PublicKey publicKeyFromJwk(")]
        digest = source[source.index("    private static String keyDigest("):
                        source.index("    private static String normalizeHostname(")]
        verified = source[source.index("    private static final class VerifiedJws {"):
                          source.index("    private static final class TokenTimes {")]
        selection = source[source.index("    private static RootSelection selectTokenRoot("):
                           source.index("    private X509TrustManager resolveNativeTrustManager(")]
        identity = source[source.index("    private static final class SignerIdentity {"):
                          source.index("    private static final class VerifiedJws {")]
        # Only Android Base64 is adapted. JSON parsing and every signature/key
        # selection, count, and rotation check below come from the current service.
        harness = r'''
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.security.*;
import java.security.interfaces.*;
import java.security.spec.*;
import java.util.*;
import org.json.*;

public class AspinJwsHost {
    private static class Base64 {
        static final int URL_SAFE = 8, NO_WRAP = 2, NO_PADDING = 1;
        static byte[] decode(String value, int flags) {
            return java.util.Base64.getUrlDecoder().decode(value);
        }
        static String encodeToString(byte[] value, int flags) {
            return java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(value);
        }
    }
    public static void main(String[] args) throws Exception {
        String token = Files.readString(Path.of(args[1]));
        PublicKey key = KeyFactory.getInstance("EC").generatePublic(
                new X509EncodedKeySpec(Files.readAllBytes(Path.of(args[2]))));
        if ("parallel".equals(args[0])) {
            PublicKey second = KeyFactory.getInstance("EC").generatePublic(
                new X509EncodedKeySpec(Files.readAllBytes(Path.of(args[3]))));
            RootSelection selected = selectTokenRoot(token, List.of(
                new SignerIdentity(key, List.of(key)), new SignerIdentity(second, List.of(second))));
            System.out.println("ROOT=" + selected.signer.currentDigest);
        } else if ("rotation".equals(args[0])) {
            if (!verifyGeneralJwsSamePayload(token, key, args[3])) {
                throw new SignatureException("Previous-key signature not found on identical payload");
            }
        } else {
            verifyJws(token, key, "tc".equals(args[0]));
        }
        System.out.println("PASS");
    }
'''
        java = cls.root / "AspinJwsHost.java"
        java.write_text(harness + methods + digest + verified + selection + identity + "}\n")
        compiled = subprocess.run(["javac", "-cp", str(cls.json_jar), str(java)],
                                  capture_output=True, text=True)
        if compiled.returncode:
            raise AssertionError("Current AOSP verification methods did not compile:\n" + compiled.stderr)
        cls.signers = []
        for index in range(64):
            cls.signers.append(("ES256", *write_key(cls.root, str(index),
                ec.generate_private_key(ec.SECP256R1()))))
        cls.token = seed_token(cls.signers[0][1])

    def verify(self, token, key_index, mode="tk", expected_payload=None):
        token_path = self.root / "input.jws"
        token_path.write_text(token)
        public = serialization.load_pem_public_key(self.signers[key_index][2].read_bytes())
        key_path = self.root / "context.der"
        key_path.write_bytes(public.public_bytes(serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo))
        command = ["java", "-cp", str(self.root) + os.pathsep + str(self.json_jar),
                   "AspinJwsHost", mode, str(token_path), str(key_path)]
        if expected_payload is not None:
            command.append(expected_payload)
        return subprocess.run(command, capture_output=True, text=True)

    def test_nonempty_signature_arrays_with_no_two_entry_cap(self):
        for count in (1, 3, 8, 16, 64):
            with self.subTest(count=count):
                token = cosigner.cosign(self.token, self.signers[1:count])
                result = self.verify(token, count - 1)
                self.assertEqual(result.returncode, 0, result.stderr)

    def test_each_owner_resolves_its_own_context(self):
        token = cosigner.cosign(self.token, self.signers[1:5])
        for index in range(5):
            result = self.verify(token, index)
            self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotEqual(self.verify(token, 5).returncode, 0)

    def test_previous_rotation_key_beyond_second_entry(self):
        token = cosigner.cosign(self.token, self.signers[1:8])
        encoded = json.loads(token)["payload"]
        result = self.verify(token, 7, "rotation", encoded)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotEqual(self.verify(token, 8, "rotation", encoded).returncode, 0)
        self.assertNotEqual(self.verify(token, 7, "rotation", encoded + "A").returncode, 0)

    def test_rejects_payload_tampering_and_empty_array(self):
        token = json.loads(cosigner.cosign(self.token, self.signers[1:4]))
        token["payload"] = cosigner.b64url(b'{"cnf":{},"iat":1,"exp":999}')
        self.assertNotEqual(self.verify(json.dumps(token), 3).returncode, 0)
        token["signatures"] = []
        self.assertNotEqual(self.verify(json.dumps(token), 0).returncode, 0)

    def test_kid_cannot_select_an_untrusted_root(self):
        value = json.loads(self.token)
        # Relabel another owner's signature with the requested key identifier.
        # A matching kid without the corresponding signature must still fail.
        public = self.signers[7][2]
        key = serialization.load_pem_public_key(public.read_bytes())
        der = key.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
        value["signatures"][0]["protected"] = cosigner.b64url(json.dumps({
            "alg": "ES256", "kid": cosigner.b64url(hashlib.sha256(der).digest())}).encode())
        self.assertNotEqual(self.verify(json.dumps(value), 7).returncode, 0)

    def test_tc_retains_single_signature_profile(self):
        self.assertEqual(self.verify(self.token, 0, "tc").returncode, 0)
        token = cosigner.cosign(self.token, self.signers[1:3])
        self.assertNotEqual(self.verify(token, 0, "tc").returncode, 0)

    def test_response_size_bound_is_preserved(self):
        aosp = Path(os.environ.get("ASPIN_AOSP_ROOT", "/mnt/code/aosp-main/aosp"))
        source = (aosp / "frameworks/base/services/core/java/com/android/server/aspin/AspinService.java").read_text()
        self.assertIn("MAX_TOKEN_BYTES = 1024 * 1024", source)
        self.assertIn("if (total > MAX_TOKEN_BYTES)", source)
        self.assertNotIn("MAX_SIGNATURES", source)

    def test_manifest_root_is_additional_not_an_override(self):
        public = serialization.load_pem_public_key(self.signers[1][2].read_bytes())
        second = self.root / "manifest.der"
        second.write_bytes(public.public_bytes(serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo))
        for token in (self.token, seed_token(self.signers[1][1])):
            result = self.verify(token, 0, "parallel", str(second))
            self.assertEqual(result.returncode, 0, result.stderr)
        # If both sign one payload, the current installed app-signing root wins.
        both = cosigner.cosign(self.token, self.signers[1:2])
        result = self.verify(both, 0, "parallel", str(second))
        key = serialization.load_pem_public_key(self.signers[0][2].read_bytes())
        digest = cosigner.b64url(hashlib.sha256(key.public_bytes(serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo)).digest())
        self.assertIn("ROOT=" + digest, result.stdout)
        forged = seed_token(self.signers[2][1])
        self.assertNotEqual(self.verify(forged, 0, "parallel", str(second)).returncode, 0)


if __name__ == "__main__":
    unittest.main()
