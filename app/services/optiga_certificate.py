"""Infineon OPTIGA Trust M device certificate check (DECISION-ELEMENT-REGISTRATION-001 E-3).

An OPTIGA_ELEMENT record says "this Infineon-certified chip was registered by ZKNOT".
The "Infineon-certified" half rests on this module and on nothing a caller writes.

WHAT IS PINNED
--------------
Two certificates, shipped in app/pki/ and pinned here by SHA-256 of their DER bytes:

  Infineon OPTIGA(TM) Trust M CA 306   issued by the root below
  Infineon OPTIGA(TM) ECC Root CA 2    self-signed

The fingerprints are DECLARED, not computed from the files: a file swapped in the repo
fails to load rather than becoming the new anchor. They match the copies in the vault
(P-Ostensor/40_SOFTWARE/pki/, fetched from pki.infineon.com 2026-08-11), and they verify
the 0xE0E0 certificates already read off nine of our own parts (WM-0001, OS-0003, OS-0011,
six Vitni Plus bring-ups; measured 2026-10-16). There is no out-of-band Infineon
fingerprint for them; that README states why the intrinsic argument is still strong.

WHAT IS NOT CHECKED, stated so nobody reads it in
-------------------------------------------------
* Revocation. CA 306 publishes a CRL; the rail does not fetch it. A chip Infineon revoked
  after the fact would still pass here.
* Other Infineon intermediates. Only CA 306 is pinned, because it is the only one we have
  seen on a part. A chip certified under another CA is REFUSED, not waved through.
  Adding one is a deliberate edit to PINNED_INTERMEDIATES with its own evidence.
* Anything about the chip's later life. The certificate proves the key was generated in an
  Infineon part. It says nothing about the device the buyer later solders it into.
"""
import hashlib
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

_PKI_DIR = Path(__file__).resolve().parent.parent / "pki"

ROOT_FILE = "infineon-optiga-ecc-root-ca-2.der"
ROOT_SHA256 = "ee0c827555c4e9012037df4257bb8aaa26084a17b13ede41cd7895c8d6c11190"

# name -> (file, declared sha256 of the DER)
PINNED_INTERMEDIATES = {
    "Infineon OPTIGA(TM) Trust M CA 306": (
        "infineon-optiga-trust-m-ca-306.der",
        "4c1d5b89c8a61b0772559b173e9093af8a29cf6dd542116569bbc2e713ed9d93",
    ),
}

# The identifier this module writes into a record. One value per pinned chain, so a
# verifier can see which chain the rail checked.
CHAIN_ID_CA306 = "infineon-optiga-trust-m-ca-306"

MAX_CERT_BYTES = 2048


class OptigaCertificateRefused(ValueError):
    """The certificate is not an Infineon OPTIGA Trust M device certificate we can verify."""


@dataclass(frozen=True)
class VerifiedOptigaCertificate:
    public_key_hex: str      # SEC1 uncompressed, 04||X||Y, lowercase
    serial_number: str       # certificate serial, lowercase hex
    subject_cn: str
    issuer_cn: str
    not_before: str          # RFC 3339 Z
    not_after: str
    chain: str               # e.g. CHAIN_ID_CA306


def _load_pinned(filename: str, declared_sha256: str) -> x509.Certificate:
    der = (_PKI_DIR / filename).read_bytes()
    actual = hashlib.sha256(der).hexdigest()
    if actual != declared_sha256:
        raise RuntimeError(
            f"Pinned Infineon certificate {filename} does not match its declared fingerprint "
            f"(have {actual}). Refusing to use it as a trust anchor."
        )
    return x509.load_der_x509_certificate(der)


_anchors = None


def _pinned():
    """(root, {issuer CN: (intermediate, chain id)}), loaded and cross-checked once."""
    global _anchors
    if _anchors is None:
        root = _load_pinned(ROOT_FILE, ROOT_SHA256)
        root.verify_directly_issued_by(root)
        inter = {}
        for cn, (fname, fp) in PINNED_INTERMEDIATES.items():
            cert = _load_pinned(fname, fp)
            cert.verify_directly_issued_by(root)
            if _cn(cert.subject) != cn:
                raise RuntimeError(f"Pinned intermediate {fname} is not {cn}")
            inter[cn] = (cert, CHAIN_ID_CA306)
        _anchors = (root, inter)
    return _anchors


def _cn(name: x509.Name) -> str:
    attrs = name.get_attributes_for_oid(x509.NameOID.COMMON_NAME)
    return attrs[0].value if attrs else ""


def _z(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def verify_optiga_certificate(der: bytes, *, at: datetime) -> VerifiedOptigaCertificate:
    """Verify a 0xE0E0 device certificate chains to a pinned Infineon CA, valid at `at`.

    `at` is the record's signed_at, not "now", so a record's verdict does not change
    with the wall clock after it is written.

    Raises OptigaCertificateRefused with a reason a jig operator can act on.
    """
    if not der or len(der) > MAX_CERT_BYTES:
        raise OptigaCertificateRefused("certificate is empty or too large")
    try:
        cert = x509.load_der_x509_certificate(der)
    except ValueError as exc:
        raise OptigaCertificateRefused(f"certificate is not DER X.509: {exc}")

    _root, intermediates = _pinned()
    issuer_cn = _cn(cert.issuer)
    pinned = intermediates.get(issuer_cn)
    if pinned is None:
        raise OptigaCertificateRefused(
            f"certificate is issued by {issuer_cn!r}, which is not a pinned Infineon CA"
        )
    issuer, chain = pinned
    if cert.issuer != issuer.subject:
        raise OptigaCertificateRefused("certificate issuer name does not match the pinned CA")
    try:
        cert.verify_directly_issued_by(issuer)
    except (InvalidSignature, ValueError, TypeError) as exc:
        raise OptigaCertificateRefused(f"certificate is not signed by {issuer_cn}: {exc or 'bad signature'}")

    if at.tzinfo is None:
        at = at.replace(tzinfo=timezone.utc)
    if not (cert.not_valid_before_utc <= at <= cert.not_valid_after_utc):
        raise OptigaCertificateRefused("certificate is not within its validity period")

    try:
        bc = cert.extensions.get_extension_for_class(x509.BasicConstraints).value
        if bc.ca:
            raise OptigaCertificateRefused("certificate is a CA certificate, not a device certificate")
    except x509.ExtensionNotFound:
        pass
    try:
        ku = cert.extensions.get_extension_for_class(x509.KeyUsage).value
        if not ku.digital_signature:
            raise OptigaCertificateRefused("certificate key is not certified for signing")
    except x509.ExtensionNotFound:
        pass

    pub = cert.public_key()
    if not isinstance(pub, ec.EllipticCurvePublicKey) or not isinstance(pub.curve, ec.SECP256R1):
        raise OptigaCertificateRefused("certificate key is not ECC P-256")
    point = pub.public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)

    return VerifiedOptigaCertificate(
        public_key_hex=point.hex(),
        serial_number=format(cert.serial_number, "x"),
        subject_cn=_cn(cert.subject),
        issuer_cn=issuer_cn,
        not_before=_z(cert.not_valid_before_utc),
        not_after=_z(cert.not_valid_after_utc),
        chain=chain,
    )
