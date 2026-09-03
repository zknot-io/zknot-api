"""TreeKnot observation submission — the ONLY unauthenticated write on this API.

Every bound here exists because this endpoint is open. An authenticated endpoint
can be generous and recover by revoking a key; this one cannot, and what it
writes is appended to a permanent public chain.

WHAT IS AND IS NOT BOUND
------------------------
The chain entry hash covers challenge_hash, not raw_artifact
(services/crypto.py::compute_chain_entry_hash). So the observation BODY lives in a
row that can be redacted if it ever has to be, while its hash stays provable and
the chain stays intact. That is deliberate and it is the property that makes an
open text-carrying endpoint survivable.
"""
from typing import List, Optional

from pydantic import BaseModel, Field, field_validator

# A signed TreeKnot record is ~1-2 KB of JSON; photographs never travel here, only
# their hashes. These caps are generous against that and still bound the damage a
# single POST can do.
MAX_OBSERVATIONS = 24
MAX_TEXT = 500
MAX_PHOTOS = 12
HEX64 = r"^[0-9a-f]{64}$"
HEX128 = r"^[0-9a-f]{128}$"


class TreePhoto(BaseModel):
    role: str = Field(..., max_length=32)
    sha256: str = Field(..., pattern=HEX64)
    bytes: Optional[int] = Field(None, ge=0, le=64 * 1024 * 1024)
    w: Optional[int] = Field(None, ge=0, le=100_000)
    h: Optional[int] = Field(None, ge=0, le=100_000)
    key: Optional[str] = Field(None, max_length=128)


class TreeIdentification(BaseModel):
    common_name: str = Field("", max_length=120)
    species_guess: str = Field("", max_length=120)
    status: str = Field("unknown", max_length=32)
    entry: str = Field("", max_length=32)
    basis: str = Field("", max_length=32)
    tool: str = Field("", max_length=64)
    human_confirmed: bool = False


class TreeLocation(BaseModel):
    latitude: float = Field(..., ge=-90, le=90)
    longitude: float = Field(..., ge=-180, le=180)
    accuracy_m: Optional[float] = Field(None, ge=0, le=100_000)
    altitude_m: Optional[float] = Field(None, ge=-500, le=10_000)
    source: str = Field("", max_length=64)
    fix_count: Optional[int] = Field(None, ge=0, le=10_000)
    spread_m: Optional[float] = Field(None, ge=0, le=100_000)


class TreeRecord(BaseModel):
    """The record the phone signed. Field names and shape must match the app
    exactly — the signature is over the canonical JSON of THIS object, so an
    extra or renamed key here means nothing verifies.
    """
    model_config = {"extra": "forbid"}

    schema_: str = Field(..., alias="schema", max_length=64)
    app_version: str = Field(..., max_length=32)
    tree_id: str = Field(..., max_length=64)
    subject_id: str = Field(..., max_length=64)
    survey_id: str = Field(..., max_length=64)
    captured_at: Optional[str] = Field(None, max_length=64)
    sealed_at: Optional[str] = Field(None, max_length=64)
    location: Optional[TreeLocation] = None
    tenure: Optional[dict] = None
    identification: Optional[TreeIdentification] = None
    observations: List[str] = Field(default_factory=list, max_length=MAX_OBSERVATIONS)
    measurements: Optional[dict] = None
    site: Optional[dict] = None
    photos: List[TreePhoto] = Field(default_factory=list, max_length=MAX_PHOTOS)
    assurance: Optional[dict] = None

    @field_validator("observations")
    @classmethod
    def _bound_each_note(cls, v):
        for note in v:
            if len(note) > MAX_TEXT:
                raise ValueError(f"an observation may be at most {MAX_TEXT} characters")
        return v


class TreeSignature(BaseModel):
    model_config = {"extra": "forbid"}
    alg: str = Field(..., max_length=32)
    key_id: str = Field(..., max_length=64)
    identity_tier: str = Field(..., max_length=32)
    public_key: str = Field(..., pattern=HEX128)
    value: str = Field(..., pattern=HEX128)


class TreeObservationSubmission(BaseModel):
    """POST /v1/tree-observations — exactly the envelope the app already makes.

    The app builds this for its share link, and /v/ verifies it in a browser.
    Taking the same object here means one shape, verified the same way in three
    places, rather than a submission format that can drift from what was signed.
    """
    model_config = {"extra": "forbid"}

    schema_: str = Field(..., alias="schema", max_length=64)
    record: TreeRecord
    record_hash: str = Field(..., pattern=HEX64)
    signature: TreeSignature
