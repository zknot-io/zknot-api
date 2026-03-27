from sqlalchemy import Column, String, DateTime, Integer, Text, ForeignKey
from sqlalchemy.sql import func
from sqlalchemy.orm import relationship
from app.database import Base


class ChainEntry(Base):
    __tablename__ = "chain_entries"

    id = Column(Integer, primary_key=True, index=True)
    chain_id = Column(String(36), nullable=False, index=True, default="default")
    position = Column(Integer, nullable=False)
    artifact_id = Column(String(36), ForeignKey("artifacts.artifact_id"), nullable=False)
    entry_hash = Column(String(64), unique=True, nullable=False)
    prev_hash = Column(String(64), nullable=True)  # null for genesis entry
    created_at = Column(DateTime(timezone=True), server_default=func.now())

    artifact = relationship("Artifact", foreign_keys=[artifact_id], primaryjoin="ChainEntry.artifact_id == Artifact.artifact_id")
