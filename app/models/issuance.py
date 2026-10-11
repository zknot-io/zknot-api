"""Server-issued, single-use challenges for device document issuance.

DECISION-DEVICE-ISSUANCE-001 (D-1, D-3). A public page cannot hold a write secret
(FR-1), so a document record from a physical device is admitted on a credential
the SERVER mints instead: a one-time challenge bound to the server's own clock and
to a record id the server chose.

Each row is spent at most once. Spending happens in the same transaction as the
artifact insert, by a conditional UPDATE that matches only an unspent, unexpired
row (services/device_issuance.py). That is the single-use guarantee: a database
predicate, not a hope. `artifact_id` is UNIQUE here and UNIQUE on `artifacts`, so a
second record under one challenge is unrepresentable twice over.

`signed_at_canonical` is the exact string the device signs. It is STORED, never
rendered from a datetime (CLAUDE.md: anything a hash commits to is stored).
"""
from sqlalchemy import Column, DateTime, String

from app.database import Base


class IssuanceChallenge(Base):
    __tablename__ = "issuance_challenges"

    nonce = Column(String(64), primary_key=True)
    artifact_id = Column(String(36), unique=True, nullable=False)
    signed_at_canonical = Column(String(32), nullable=False)
    issued_at = Column(DateTime(timezone=True), nullable=False)
    expires_at = Column(DateTime(timezone=True), nullable=False, index=True)
    # NULL until spent. Spent rows are kept: one per record, and they are the
    # server's own evidence of the window the record was signed in.
    spent_at = Column(DateTime(timezone=True), nullable=True, index=True)
