#!/usr/bin/env python3
"""Generate disposable cross-signed chains for host and Android tests.

No public CA issuance, device access, or production certificate changes.
Private fixture keys are generated only under the selected output directory.
"""

import argparse
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID


def name(common_name):
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])


def certificate(subject, key, issuer, issuer_key, ca=False, hostname=None):
    now = datetime.now(timezone.utc)
    builder = (x509.CertificateBuilder()
        .subject_name(subject).issuer_name(issuer).public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + timedelta(days=7))
        .add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
        .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(issuer_key.public_key()), critical=False)
        .add_extension(x509.KeyUsage(digital_signature=True, content_commitment=False,
            key_encipherment=False, data_encipherment=False, key_agreement=False,
            key_cert_sign=ca, crl_sign=ca, encipher_only=False, decipher_only=False), critical=True))
    if hostname:
        builder = builder.add_extension(
            x509.SubjectAlternativeName([x509.DNSName(hostname)]), critical=False
        ).add_extension(x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
    return builder.sign(issuer_key, hashes.SHA256())


def generate(output, hostname="cross-sign.example"):
    if output.exists() and any(output.iterdir()):
        raise FileExistsError("Cross-sign fixtures require an empty output directory")
    output.mkdir(parents=True, exist_ok=True)
    roots = [ec.generate_private_key(ec.SECP256R1()) for _ in range(2)]
    root_names = [name("ASPin Cross-Sign Root A"), name("ASPin Cross-Sign Root B")]
    root_certs = [certificate(n, k, n, k, ca=True) for n, k in zip(root_names, roots)]
    shared = ec.generate_private_key(ec.SECP256R1())
    shared_name = name("ASPin Cross-Signed Intermediate")
    issuers = [certificate(shared_name, shared, n, k, ca=True) for n, k in zip(root_names, roots)]
    leaf_key = ec.generate_private_key(ec.SECP256R1())
    leaf = certificate(name(hostname), leaf_key, shared_name, shared, hostname=hostname)
    rogue_key = ec.generate_private_key(ec.SECP256R1())
    rogue_ca = certificate(shared_name, rogue_key, root_names[0], roots[0], ca=True)
    rogue_leaf_key = ec.generate_private_key(ec.SECP256R1())
    rogue_leaf = certificate(name(hostname), rogue_leaf_key, shared_name, rogue_key, hostname=hostname)
    certs = dict(zip(("root-a.pem", "root-b.pem", "direct-a.pem", "direct-b.pem"), root_certs + issuers))
    certs.update({"leaf.pem": leaf, "rogue-direct.pem": rogue_ca, "rogue-leaf.pem": rogue_leaf})
    for filename, cert in certs.items():
        (output / filename).write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    for filename, key in (("leaf.key", leaf_key), ("rogue-leaf.key", rogue_leaf_key)):
        target = output / filename
        target.touch(mode=0o600, exist_ok=False)
        target.write_bytes(key.private_bytes(serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    def pem(cert):
        return cert.public_bytes(serialization.Encoding.PEM)
    (output / "trusted-roots.pem").write_bytes(b"".join(map(pem, root_certs)))
    # Deliberately include ancestors and a duplicate; neither belongs in IssuerSet.
    (output / "issuer-variants.pem").write_bytes(pem(issuers[0]) + pem(root_certs[0])
        + pem(issuers[1]) + pem(root_certs[1]) + pem(issuers[0]))
    (output / "chain-a.pem").write_bytes(pem(leaf) + pem(issuers[0]))
    (output / "chain-b.pem").write_bytes(pem(leaf) + pem(issuers[1]))
    (output / "rogue-chain.pem").write_bytes(pem(rogue_leaf) + pem(rogue_ca))
    (output / "rogue-padded-chain.pem").write_bytes(pem(rogue_leaf) + pem(rogue_ca) + pem(issuers[0]))
    return certs


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--hostname", default="cross-sign.example")
    args = parser.parse_args()
    generate(args.output_dir, args.hostname)
    print("Generated disposable cross-sign certificate fixtures")


if __name__ == "__main__":
    main()
