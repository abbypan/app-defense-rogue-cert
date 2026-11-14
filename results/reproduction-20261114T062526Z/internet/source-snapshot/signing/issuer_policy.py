"""Select every supplied direct-issuer certificate variant, not CA ancestors."""

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization


def direct_issuer_certificates(leaf, candidates):
    """Return distinct CA DER certificates that actually verify this leaf.

    Publishers supply all supported alternate-chain/cross-sign certificates.
    This helper does not discover certificates on the network or turn the
    complete chain into an issuer allowlist.
    """
    result = []
    seen = set()
    for candidate in candidates:
        if candidate.subject != leaf.issuer:
            continue
        try:
            if not candidate.extensions.get_extension_for_class(
                    x509.BasicConstraints).value.ca:
                continue
            try:
                if not candidate.extensions.get_extension_for_class(
                        x509.KeyUsage).value.key_cert_sign:
                    continue
            except x509.ExtensionNotFound:
                pass
            leaf.verify_directly_issued_by(candidate)
        except (x509.ExtensionNotFound, InvalidSignature, ValueError):
            continue
        der = candidate.public_bytes(serialization.Encoding.DER)
        if der not in seen:
            seen.add(der)
            result.append(candidate)
    if not result:
        raise ValueError("No supplied CA certificate directly verifies the leaf")
    return result
