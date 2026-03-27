from sqlalchemy import Column, String, DateTime, JSON, Integer, Enum, Text
from sqlalchemy.sql import func
from app.database import Base
import enum


class ArtifactType(str, enum.Enum):
    ZKEY_SIGN = "ZKEY_SIGN"
    POWER_SESSION = "POWER_SESSION"
    TRUST_SEAL = "TRUST_SEAL"
    COMBINED_SESSION = "COMBINED_SESSION"


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
