from sqlalchemy import Column, String, DateTime, JSON, Integer, Enum, Text
from sqlalchemy.sql import func
from app.database import Base
import enum


class ArtifactType(str, enum.Enum):
    ZKEY_SIGN = "ZKEY_SIGN"
    POWER_SESSION = "POWER_SESSION"
    TRUST_SEAL = "TRUST_SEAL"
    COMBINED_SESSION = "COMBINED_SESSION"
    POWERVERIFY_UNIT = "POWERVERIFY_UNIT"  # Manufacturing birth certificate (PAT-002, PAT-019)
    DEV_SIGN = "DEV_SIGN"  # Software dev-key record (rail bootstrap; SELF-ASSERTED, no presence claim)
    WITNESSMARK_UNIT = "WITNESSMARK_UNIT"  # Device-signed WitnessMark birth record (real ECDSA via OPTIGA)
    VITNI_UNIT = "VITNI_UNIT"  # Device-signed Vitni birth record (ECDSA via ATECC608B, D1-gated)
    # VITNI_UNIT is its own type on purpose. Idempotency for unit artifacts is keyed on
    # (serial_number, artifact_type), which is what keeps WM and PV serials in separate
    # namespaces so they can never collide. Filing a Vitni under POWERVERIFY_UNIT or
    # WITNESSMARK_UNIT would merge two product lines in the chain and give up that
    # property. WITNESSMARK_UNIT in particular is Ostensor's -- the enum value is frozen
    # as a live prod value with display-name mapping only, so it must not be reused.
    #
    # Adding a value here does NOT change the database. Schema comes from
    # Base.metadata.create_all(), which never alters existing types. See
    # alembic/versions/0004_vitni_unit_type.py.


class Artifact(Base):
    __tablename__ = "artifacts"

    id = Column(Integer, primary_key=True, index=True)
    artifact_id = Column(String(36), unique=True, index=True, nullable=False)
    artifact_type = Column(Enum(ArtifactType), nullable=False)
    device_id = Column(String(128), nullable=False, index=True)
    session_id = Column(String(36), nullable=True, index=True)
    challenge_hash = Column(String(64), nullable=False)
    signature = Column(Text, nullable=False)
    public_key = Column(Text, nullable=False)
    short_code = Column(String(16), unique=True, index=True, nullable=False)
    signed_at = Column(DateTime(timezone=True), nullable=False)
    metadata_ = Column("metadata", JSON, nullable=True, default={})
    raw_artifact = Column(JSON, nullable=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
