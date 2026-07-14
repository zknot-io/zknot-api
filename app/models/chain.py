from sqlalchemy import Column, String, DateTime, Integer, Text, ForeignKey, UniqueConstraint
from sqlalchemy.sql import func
from sqlalchemy.orm import relationship
from app.database import Base


class ChainEntry(Base):
    __tablename__ = "chain_entries"

    # F1 — fork prevention is enforced here, in the schema, not only by the
    # advisory lock in services/chain.py. The lock serializes the happy path;
    # these constraints make the bad states unrepresentable regardless of caller.
    #
    # uq_chain_entries_chain_position: two entries at one position IS the fork.
    #   The pre-existing UNIQUE on entry_hash does NOT cover it — racing entries
    #   carry different artifact_ids, so their hashes differ and the index
    #   accepts every one of them.
    # uq_chain_entries_chain_artifact: one entry per artifact per chain — the
    #   duplicate-business-event constraint, which makes replay idempotent
    #   independently of chain ordering.
    __table_args__ = (
        UniqueConstraint("chain_id", "position", name="uq_chain_entries_chain_position"),
        UniqueConstraint("chain_id", "artifact_id", name="uq_chain_entries_chain_artifact"),
    )

    id = Column(Integer, primary_key=True, index=True)
    chain_id = Column(String(36), nullable=False, index=True, default="default")
    position = Column(Integer, nullable=False)
    artifact_id = Column(String(36), ForeignKey("artifacts.artifact_id"), nullable=False)
    entry_hash = Column(String(64), unique=True, nullable=False)
    prev_hash = Column(String(64), nullable=True)  # null for genesis entry
    created_at = Column(DateTime(timezone=True), server_default=func.now())

    artifact = relationship("Artifact", foreign_keys=[artifact_id], primaryjoin="ChainEntry.artifact_id == Artifact.artifact_id")
