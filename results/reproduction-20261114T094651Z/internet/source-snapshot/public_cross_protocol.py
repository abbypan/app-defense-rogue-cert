"""Public-CA certificate fixtures and protocol; never manufacture a CA."""
import base64
import hashlib
from pathlib import Path
import shutil
import subprocess

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization


def identifier(cert):
    return "sha256:" + base64.urlsafe_b64encode(cert.fingerprint(hashes.SHA256())).rstrip(b"=").decode()


def public_der(cert):
    return cert.public_key().public_bytes(serialization.Encoding.DER,
                                          serialization.PublicFormat.SubjectPublicKeyInfo)


def plan():
    # Publication order is monotone; changing a certificate never resets H_c.
    return (
        ("le-only-le", "le", "le-only", True, False),
        ("le-only-zerossl", "zerossl", "le-only", False, False),
        ("le-only-padded-zerossl", "padded-zerossl", "le-only", False, True),
        ("dual-le-full", "le", "dual", True, False),
        ("dual-le-short", "le-short", "dual", True, False),
        ("dual-zerossl", "zerossl", "dual", True, False),
        ("ancestor-only-le", "le", "ancestor-only", False, False),
        ("zerossl-only-zerossl", "zerossl", "zerossl-only", True, False),
        ("zerossl-only-le", "le", "zerossl-only", False, False),
    )


def prepare(certificates, output, hostname):
    output.mkdir(parents=True, exist_ok=True)
    providers = {"le": certificates / "letsencrypt/real-fullchain.pem",
                 "zerossl": certificates / "zerossl/rogue-fullchain.pem"}
    parsed = {name: x509.load_pem_x509_certificates(path.read_bytes()) for name, path in providers.items()}
    if any(len(chain) < 2 for chain in parsed.values()): raise ValueError("Missing public issuing CA")
    csr = x509.load_pem_x509_csr((certificates / "server.csr.pem").read_bytes())
    key = serialization.load_pem_private_key((certificates / "server-privkey.pem").read_bytes(), None)
    expected = csr.public_key().public_bytes(serialization.Encoding.DER,
                                            serialization.PublicFormat.SubjectPublicKeyInfo)
    if not csr.is_signature_valid or key.public_key().public_bytes(serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo) != expected:
        raise ValueError("Invalid shared PKCS#10 request/private key")
    for name, chain in parsed.items():
        if public_der(chain[0]) != expected: raise ValueError("CA leaf does not match the ONE shared CSR")
        if chain[0].extensions.get_extension_for_class(x509.SubjectAlternativeName).value.get_values_for_type(
                x509.DNSName) != [hostname]: raise ValueError("Unexpected public-certificate SAN")
        for child, parent in zip(chain, chain[1:]): child.verify_directly_issued_by(parent)
        for label, cert in (("leaf", chain[0]), ("issuer", chain[1])):
            (output / (name + "-" + label + ".pem")).write_bytes(cert.public_bytes(serialization.Encoding.PEM))
        shutil.copyfile(providers[name], output / (name + "-fullchain.pem"))
    a, b = parsed["le"], parsed["zerossl"]
    if a[0] == b[0] or identifier(a[1]) == identifier(b[1]):
        raise ValueError("Two independent public-CA issuances required")
    if a[0].subject != b[0].subject: raise ValueError("Public leaves must share Subject/SAN")
    # Current LE hierarchy: leaf -> YE* -> cross-signed Root YE ->
    # cross-signed ISRG Root X2 -> system ISRG Root X1. The short presentation
    # omits the final cross-certificate and can terminate at system Root X2.
    # Do not invent an alternate chain if this condition no longer holds.
    if len(a) < 4 or a[-1].subject.rfc4514_string().split(",")[0] != "CN=ISRG Root X2":
        raise ValueError("Issued LE chain has no supported public X2/X1 alternate presentation")
    def pem(certs): return b"".join(c.public_bytes(serialization.Encoding.PEM) for c in certs)
    (output / "le-short-fullchain.pem").write_bytes(pem(a[:-1]))
    (output / "padded-zerossl-fullchain.pem").write_bytes(pem(b) + pem([a[1]]))
    shutil.copyfile(certificates / "server.csr.pem", output / "server.csr.pem")
    for label, chain in (("le", a), ("le-short", a[:-1]), ("zerossl", b)):
        bundle = output / (label + "-issuers.pem")
        bundle.write_bytes(pem(chain[1:]))
        result = subprocess.run(["openssl", "verify", "-purpose", "sslserver", "-verify_hostname", hostname,
                                 "-untrusted", str(bundle), str(output / ("zerossl-leaf.pem" if label == "zerossl" else "le-leaf.pem"))],
                                capture_output=True, text=True)
        if result.returncode: raise ValueError("Public path verification failed: " + result.stderr)
    return {"same_csr_public_key": True, "same_leaf_certificate": False,
            "direct_issuer_same_subject_key": a[1].subject == b[1].subject and public_der(a[1]) == public_der(b[1]),
            "public_cross_sign_location": "LE ancestor CAs, not the direct issuer",
            "csr_sha256": hashlib.sha256((output / "server.csr.pem").read_bytes()).hexdigest(),
            "issuer_sets": {"le-only": [identifier(a[1])], "dual": [identifier(a[1]), identifier(b[1])],
                            "ancestor-only": [identifier(a[2])], "zerossl-only": [identifier(b[1])]},
            "issuers": {name: chain[1].subject.rfc4514_string() for name, chain in parsed.items()},
            "chains": {name: [{"subject": c.subject.rfc4514_string(), "issuer": c.issuer.rfc4514_string(),
                                "id": identifier(c)} for c in chain] for name, chain in parsed.items()}}
