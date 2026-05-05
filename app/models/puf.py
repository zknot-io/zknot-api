"""
PUF (Physical Unclonable Function) records.

Holographic glitter encapsulation creates a unique random light-scattering
signature per unit. Photographed at QC under standardized conditions, hashed
via perceptual hashing, stored as a baseline. Customers can re-photograph
later and the system compares Hamming distance to detect tampering or
counterfeit units.

PUF records are NOT in the artifact chain — they're not signed events.
They are auxiliary identity data tied to a unit's POWERVERIFY_UNIT artifact.
"""
from sqlalchemy import Column, String, DateTime, Integer, JSON, ForeignKey
from sqlalchemy.sql import func
from sqlalchemy.orm import relationship
from app.database import Base


class PufRecord(Base):
    __tablename__ = "puf_records"

    id = Column(Integer, primary_key=True, index=True)

    # Links to the unit's POWERVERIFY_UNIT artifact via short_code
    # (artifact_id would also work, but short_code is the user-facing identifier)
    short_code = Column(String(16), ForeignKey("artifacts.short_code"),
                        nullable=False, index=True)

    record_type = Column(String(16), nullable=False)  # 'enrollment' or 'verification'
    perceptual_hash = Column(String(64), nullable=False)  # phash hex (256-bit)
    capture_metadata = Column(JSON, nullable=False, default={})  # camera, lighting, etc

    # For verification records only:
    matched_baseline = Column(Integer, nullable=True)   # 1=match, 0=no match
    hamming_distance = Column(Integer, nullable=True)   # bits differing from baseline
    confidence = Column(String(16), nullable=True)      # 'high', 'medium', 'low', 'fail'

    captured_at = Column(DateTime(timezone=True), server_default=func.now())

    artifact = relationship(
        "Artifact",
        foreign_keys=[short_code],
        primaryjoin="PufRecord.short_code == Artifact.short_code",
    )
