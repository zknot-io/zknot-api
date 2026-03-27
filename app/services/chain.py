from sqlalchemy.orm import Session
from sqlalchemy import func
from app.models.chain import ChainEntry
from app.models.artifact import Artifact
from app.services.crypto import compute_chain_entry_hash
from typing import Optional, Tuple
import logging

logger = logging.getLogger(__name__)

DEFAULT_CHAIN = "default"


def get_chain_head(db: Session, chain_id: str = DEFAULT_CHAIN) -> Optional[ChainEntry]:
    """Return the most recent chain entry (highest position)."""
    return (
        db.query(ChainEntry)
        .filter(ChainEntry.chain_id == chain_id)
        .order_by(ChainEntry.position.desc())
        .first()
    )


def get_chain_length(db: Session, chain_id: str = DEFAULT_CHAIN) -> int:
    return db.query(func.count(ChainEntry.id)).filter(ChainEntry.chain_id == chain_id).scalar() or 0


def append_to_chain(
    db: Session,
    artifact: Artifact,
    chain_id: str = DEFAULT_CHAIN,
) -> ChainEntry:
    """
    PAT-004: Append an artifact to the chain.
    - Fetch current head to get prev_hash and position
    - Compute deterministic entry_hash covering artifact content + prev_hash
    - Write immutable chain entry
    - Never overwrites, never deletes
    """
    head = get_chain_head(db, chain_id)
    position = (head.position + 1) if head else 0
    prev_hash = head.entry_hash if head else None

    entry_hash = compute_chain_entry_hash(
        position=position,
        artifact_id=artifact.artifact_id,
        challenge_hash=artifact.challenge_hash,
        signature=artifact.signature,
        signed_at=artifact.signed_at.isoformat(),
        prev_hash=prev_hash,
    )

    entry = ChainEntry(
        chain_id=chain_id,
        position=position,
        artifact_id=artifact.artifact_id,
        entry_hash=entry_hash,
        prev_hash=prev_hash,
    )
    db.add(entry)
    db.commit()
    db.refresh(entry)
    logger.info(f"Chain append: position={position} artifact={artifact.artifact_id} hash={entry_hash[:16]}...")
    return entry


def verify_chain_integrity(db: Session, chain_id: str = DEFAULT_CHAIN) -> Tuple[bool, Optional[int]]:
    """
    Walk the entire chain, recompute every entry_hash, verify linkage.
    Returns (True, None) if intact, (False, position) at first failure.
    """
    entries = (
        db.query(ChainEntry)
        .filter(ChainEntry.chain_id == chain_id)
        .order_by(ChainEntry.position.asc())
        .all()
    )

    if not entries:
        return True, None

    for entry in entries:
        artifact = db.query(Artifact).filter(Artifact.artifact_id == entry.artifact_id).first()
        if not artifact:
            return False, entry.position

        expected_hash = compute_chain_entry_hash(
            position=entry.position,
            artifact_id=artifact.artifact_id,
            challenge_hash=artifact.challenge_hash,
            signature=artifact.signature,
            signed_at=artifact.signed_at.isoformat(),
            prev_hash=entry.prev_hash,
        )

        if expected_hash != entry.entry_hash:
            logger.warning(f"Chain integrity failure at position {entry.position}")
            return False, entry.position

        # Verify linkage to previous entry
        if entry.position > 0:
            prev = entries[entry.position - 1]
            if entry.prev_hash != prev.entry_hash:
                return False, entry.position

    return True, None


def get_entry_by_artifact_id(db: Session, artifact_id: str) -> Optional[ChainEntry]:
    return db.query(ChainEntry).filter(ChainEntry.artifact_id == artifact_id).first()
