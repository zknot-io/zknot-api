"""
Per-product API keys for chain-write endpoints (FD-A3).

The API key identifies the *caller*; the trust anchor
(services/trust_anchor.py) identifies the *signer*. Both are required on a
write. A leaked API key must not be enough to forge a record — it only buys the
ability to submit signatures that still have to come from an anchored key.

Keys live in one env var, matching the existing ZKNOT_PROVISIONING_TOKEN
pattern rather than inventing a second mechanism:

    ZKNOT_ATTEST_API_KEYS="hashstamp-worker:<secret>,provisioner:<secret>"

Empty/unset is FAIL-CLOSED in production and FAIL-OPEN in development, because
a dev box with no secrets configured should still be able to run the test suite
— but a production deploy that forgot the secret must refuse writes rather than
silently accept anonymous ones. That asymmetry is deliberate: the failure mode
of the old code was exactly "accepts anonymous writes", and a config mistake
must not resurrect it.
"""

import hmac
import os
from typing import Dict, Optional

from fastapi import Header, HTTPException

from app.config import settings

_ENV_VAR = "ZKNOT_ATTEST_API_KEYS"


def _parse_keys(raw: str) -> Dict[str, str]:
    """Parse "label:secret,label:secret" into {secret: label}.

    Keyed by secret because lookup is by presented secret. Malformed entries
    are skipped rather than raising: one fat-fingered pair in an env var must
    not take the whole API down, and the fail-closed check below still refuses
    writes if nothing valid parsed.
    """
    out: Dict[str, str] = {}
    for chunk in (raw or "").split(","):
        chunk = chunk.strip()
        if not chunk or ":" not in chunk:
            continue
        label, _, secret = chunk.partition(":")
        label, secret = label.strip(), secret.strip()
        if label and secret:
            out[secret] = label
    return out


def configured_keys() -> Dict[str, str]:
    """Current {secret: label} map, read fresh so a rotation needs no restart."""
    return _parse_keys(os.environ.get(_ENV_VAR, ""))


def _is_production() -> bool:
    return (settings.environment or "").lower() in ("production", "prod")


def resolve_caller(presented: Optional[str]) -> str:
    """Return the caller label for a presented key, or raise 401.

    Constant-time comparison against every configured secret: a plain `in`
    lookup on a dict is fast, but timing-safe comparison costs nothing at this
    key count and removes the question entirely.
    """
    keys = configured_keys()

    if not keys:
        if _is_production():
            # Fail closed. An unconfigured production API must not accept
            # anonymous chain writes - that was API-01.
            raise HTTPException(
                status_code=503,
                detail=(
                    "Chain writes are unavailable: server is missing "
                    f"{_ENV_VAR} configuration."
                ),
            )
        return "dev-unauthenticated"

    if not presented:
        raise HTTPException(
            status_code=401,
            detail="Missing API key. Send it as 'X-API-Key: <key>'.",
        )

    for secret, label in keys.items():
        if hmac.compare_digest(presented, secret):
            return label

    raise HTTPException(status_code=401, detail="Invalid API key.")


def require_api_key(x_api_key: Optional[str] = Header(default=None)) -> str:
    """FastAPI dependency. Returns the caller label for logging/attribution."""
    return resolve_caller(x_api_key)
