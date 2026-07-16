"""
Trust anchor for chain writes (API-01).

Before this table existed, `verify_signature()` checked a caller-supplied
signature against a caller-supplied public key. That is self-referential: it
proves only that whoever produced the signature holds the private key for the
public key they also chose. Anyone could generate a P-256 keypair, sign any
digest, POST /v1/attest, and receive a permanent public chain record that
/v1/verify then reported as `verified: true`.

This table is the missing half: the set of public keys ZKNOT actually vouches
for. A signature is now evidence only if the key that made it is one we
recognise.

FD-A3 (founder-decided 2026-07-15): allowlist + per-product API keys. The API
key says *which caller* is talking; the allowlist says *which signer* is
trusted. They answer different questions and both are required — a leaked API
key must not be sufficient to forge a record.
"""

from sqlalchemy import Boolean, Column, DateTime, Integer, String, Text
from sqlalchemy.sql import func

from app.database import Base


class TrustedKey(Base):
    """A public key ZKNOT vouches for as a legitimate chain signer.

    `public_key_norm` is the lookup column: uncompressed P-256 X||Y, lowercase
    hex, no `04` prefix. Callers may send the key in any accepted form; it is
    normalised before comparison so that a cosmetic difference in encoding can
    never decide whether a record is trusted.
    """

    __tablename__ = "trusted_keys"

    id = Column(Integer, primary_key=True, index=True)

    # Normalised lookup key — see normalize_public_key() in services/trust_anchor.
    public_key_norm = Column(String(128), unique=True, index=True, nullable=False)

    # Human-facing identity of the signer, surfaced by /v1/verify as `anchor`.
    # e.g. "hashstamp-worker", "powerverify-unit-0042", "witnessmark-WM-0001".
    label = Column(String(128), nullable=False)

    # Product family. Lets a whole family be revoked or audited at once.
    # e.g. "hashstamp", "powerverify", "witnessmark", "provisioner".
    product = Column(String(64), nullable=False, index=True)

    # Revocation without deletion: history must stay auditable. A record signed
    # by a key that was trusted at signing time keeps its provenance; setting
    # active=False stops NEW appends from that key.
    active = Column(Boolean, nullable=False, default=True, server_default="true")

    # Why this key is trusted — provisioning run, ceremony, bench session.
    # Free text on purpose; the audit trail matters more than the schema.
    note = Column(Text, nullable=True)

    added_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    revoked_at = Column(DateTime(timezone=True), nullable=True)

    def __repr__(self) -> str:  # pragma: no cover - debug aid
        state = "active" if self.active else "revoked"
        return f"<TrustedKey {self.label} ({self.product}, {state})>"
