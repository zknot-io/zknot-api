from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.config import settings
from app.database import init_db
from app.routers import verify, attest
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(
    title="ZKNOT Platform API",
    description=(
        "Physics enforces. Math proves. You verify.\n\n"
        "Hardware attestation and chain-of-custody API for ZKNOT evidence devices. "
        "POST an attestation artifact from a ZKKey or PowerVerify device, get back a "
        "short code (PAT-010). Anyone can verify it at verifyknot.io with no login required."
    ),
    version="0.1.0",
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


@app.on_event("startup")
def on_startup():
    init_db()
    logger.info("ZKNOT API started — database tables initialized")


@app.get("/", tags=["health"])
def root():
    return {
        "service": "ZKNOT Platform API",
        "status": "operational",
        "version": "0.1.0",
        "verify": "GET /v1/verify/{short_code}",
        "attest": "POST /v1/attest",
        "docs": "/docs",
    }


@app.get("/health", tags=["health"])
def health():
    return {"status": "ok"}
