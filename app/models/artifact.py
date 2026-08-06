from sqlalchemy import Column, String, DateTime, JSON, Integer, Enum, Text, event
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
    SELFKNOT_UNIT = "SELFKNOT_UNIT"  # Device-signed SelfKnot birth record (ECDSA via ATECC608B, open firmware)
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


# The birth-record ("unit") types — the set over which one device has exactly one
# record. DECISION-ARTIFACT-TYPE-001 B-6/B-7.
#
# THIS LIST AND `UNIT_TYPES` IN alembic/versions/0006_unit_device_uniqueness.py ARE
# ONE FACT WRITTEN IN TWO PLACES, AND THEY MUST MOVE TOGETHER. 0006's partial unique
# index uses that list as its predicate; provision_unit()'s idempotency lookup uses
# this one. If they diverge, the lookup misses a row the index forbids and the honest
# 409 becomes an IntegrityError 500 — which is exactly the defect B-7 exists to fix.
# The migration hardcodes its own copy on purpose (a migration must not import app
# code that will drift under it), so the duplication is deliberate, not an oversight.
#
# SELFKNOT_UNIT IS DELIBERATELY ABSENT. It exists in the enum above but NOT in the
# production `artifacttype` type — migration 0007 is written and NOT applied, blocked
# on an operator ruling (journal 2026-08-01, open item #5). Naming it here would emit
# a label the database does not have and error the query. Add it here and to 0006's
# predicate in the same change as 0007, or not at all.
UNIT_ARTIFACT_TYPES = (
    ArtifactType.POWERVERIFY_UNIT,
    ArtifactType.WITNESSMARK_UNIT,
    ArtifactType.VITNI_UNIT,
)


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
    # B4 — the exact string the chain hash commits to, STORED rather than
    # re-rendered. `entry_hash` covers signed_at as a string, and the previous
    # code re-derived it with .isoformat() on every read; psycopg renders a
    # timestamptz in the session's TimeZone, so chain integrity was a function of
    # a mutable server setting (measured: Etc/UTC vs America/Denver renders the
    # same row as +00 and -06, and every recomputed hash then differs).
    #
    # Populated by the before_insert listener below, never by a caller. Migration
    # 0008 backfills it with the rendering the existing hashes were already built
    # from, and REFUSES if that does not reproduce all of them — so no stored
    # hash changes value, and none of the published chain_prev_hash values move.
    #
    # THE RULE THIS INSTANTIATES: anything a hash commits to must be stored,
    # never rendered.
    signed_at_canonical = Column(String(64), nullable=False)
    metadata_ = Column("metadata", JSON, nullable=True, default={})
    raw_artifact = Column(JSON, nullable=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now())


@event.listens_for(Artifact, "before_insert")
def _freeze_signed_at_rendering(_mapper, _connection, target):
    """Capture the signed_at rendering ONCE, at insert, as data.

    Here rather than at each call site on purpose: artifacts are minted by
    /v1/attest, provision_unit(), trustseal and the test fixtures, and a rule
    enforced in four places is a rule that gets forgotten in a fifth. A mapper
    event cannot be bypassed by adding a new writer.

    Deliberately NOT normalising (no forced UTC, no Z-suffix, no microsecond
    padding). Normalising here would render new records differently from the 77
    already on the chain for no gain — the point is to stop re-deriving the
    string, not to change it. `signed_at` itself is untouched: it is covered by
    the "canonical-record" identity binding, so altering it would break
    signatures.
    """
    if target.signed_at_canonical is None and target.signed_at is not None:
        target.signed_at_canonical = target.signed_at.isoformat()
