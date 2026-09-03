"""ZKNOT Platform API — TreeKnot observation submission.

POST /v1/tree-observations

THE ONLY UNAUTHENTICATED WRITE ON THIS API. That is deliberate: TreeKnot is meant
to be usable by anyone who installs the web app, and requiring an API key to
record a tree would mean no records. But it is a permanent public chain, so the
endpoint carries its own limits (services/tree_observation.py) rather than
borrowing the API-key gate the other writers rely on.

WHAT A CALLER GETS BACK
-----------------------
The same ArtifactResponse shape as /v1/attest, including short_code — so
verifyknot.io/v/{short_code} is known immediately and resolves with no verifier
change, because the verifier does not branch on artifact type.

201 a new receipt was chained
200 this record was already submitted; the stored receipt is returned
400 the record does not verify — bad signature, or the hash does not reproduce
422 the submission does not fit the schema bounds
429 rate limited (per key, or the global daily cap)
503 submissions are closed (TREEKNOT_SUBMIT_ENABLED=0)
"""

from fastapi import APIRouter, Depends, HTTPException, Response
from sqlalchemy.orm import Session

from app.database import get_db
from app.schemas.artifact import ArtifactResponse
from app.schemas.tree import TreeObservationSubmission
from app.services.chain import get_entry_by_artifact_id
from app.services.tree_observation import SubmissionRefused, submit_observation

router = APIRouter(prefix="/v1", tags=["treeknot"])


@router.post("/tree-observations", response_model=ArtifactResponse)
def submit_tree_observation(
    payload: TreeObservationSubmission,
    response: Response,
    db: Session = Depends(get_db),
):
    """File a phone-signed tree observation and chain ZKNOT's receipt of it.

    No API key. See the module docstring for why, and
    services/tree_observation.py for what holds the door instead.
    """
    try:
        artifact, chain_entry, was_existing = submit_observation(db, payload)
    except SubmissionRefused as refused:
        raise HTTPException(status_code=refused.status, detail=str(refused))

    # On a re-post ingest_artifact returns the stored row and no entry; the
    # chained entry is still the one that matters, so look it up rather than
    # returning a response that omits it.
    if chain_entry is None:
        chain_entry = get_entry_by_artifact_id(db, artifact.artifact_id)
    if chain_entry is None:
        raise HTTPException(
            status_code=500,
            detail="the record is stored but has no chain entry — refusing to "
                   "report a position that does not exist",
        )

    response.status_code = 200 if was_existing else 201
    if was_existing:
        response.headers["X-Already-Existed"] = "true"

    return ArtifactResponse(
        artifact_id=artifact.artifact_id,
        artifact_type=artifact.artifact_type,
        device_id=artifact.device_id,
        session_id=artifact.session_id,
        challenge_hash=artifact.challenge_hash,
        short_code=artifact.short_code,
        signed_at=artifact.signed_at,
        chain_position=chain_entry.position,
        chain_prev_hash=chain_entry.prev_hash,
        entry_hash=chain_entry.entry_hash,
        metadata=artifact.metadata_,
    )
