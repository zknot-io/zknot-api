from fastapi import FastAPI, Depends, Response
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import text
from sqlalchemy.orm import Session
from app.config import settings
from app.database import init_db, get_db
from app.routers import verify, attest, units, trustseal
import logging
import os

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

VERSION = "0.3.0"


def build_id() -> str:
    """Deploy marker — lets a rollout be confirmed WITHOUT minting a seal.

    Railway injects RAILWAY_GIT_COMMIT_SHA at build time, so each deploy reports
    the exact commit it was built from. Poll GET / and wait for `build` to show
    the new short SHA; that beats timestamp-guessing and registers no chain
    records. Falls back to VERSION when running outside Railway (local/dev),
    where there is no per-commit marker.
    """
    sha = os.environ.get("RAILWAY_GIT_COMMIT_SHA", "").strip()
    return sha[:7] if sha else VERSION

app = FastAPI(
    title="ZKNOT Platform API",
    description=(
        "Physics enforces. Math proves. You verify.\n\n"
        "Hardware attestation and chain-of-custody API for ZKNOT evidence devices. "
        "POST an attestation artifact from a ZKKey or PowerVerify device, get back a "
        "short code (PAT-010). Anyone can verify it at verifyknot.io with no login required."
    ),
    version=VERSION,
    contact={"name": "ZKNOT, Inc.", "email": "ops@zknot.io"},
    docs_url="/docs",
    redoc_url="/redoc",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_credentials=True,
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)

app.include_router(verify.router)
app.include_router(attest.router)
app.include_router(units.router)
app.include_router(trustseal.router)


@app.on_event("startup")
def on_startup():
    init_db()
    logger.info("ZKNOT API started — database tables initialized")


@app.get("/", tags=["health"])
def root():
    return {
        "service": "ZKNOT Platform API",
        "status": "operational",
        "version": VERSION,
        "build": build_id(),
        "verify": "GET /v1/verify/{short_code}",
        "attest": "POST /v1/attest",
        "seal_register": "POST /v1/seal/register",
        "provision": "POST /v1/units/provision",
        "docs": "/docs",
    }


@app.get("/health", tags=["health"])
def health():
    """Liveness — static, no dependencies. Safe as Railway's internal healthcheck."""
    return {"status": "ok", "build": build_id()}


@app.get("/healthz", tags=["health"])
def healthz(response: Response, db: Session = Depends(get_db)):
    """Readiness — executes a trivial query so a dropped or exhausted DB pool
    surfaces as HTTP 503 instead of a silent Cloudflare 520.

    Point the external uptime monitor HERE. Keep Railway's own healthcheck on
    /health (liveness) so a transient DB blip can't trigger a container restart
    loop — the pool already uses pool_pre_ping to recover stale connections.
    """
    try:
        db.execute(text("SELECT 1"))
        return {"status": "ok", "db": "ok", "build": build_id()}
    except Exception as exc:  # exercised only against a live DB
        logger.error("healthz DB check failed: %s", exc)
        response.status_code = 503
        return {"status": "degraded", "db": "error", "build": build_id()}

