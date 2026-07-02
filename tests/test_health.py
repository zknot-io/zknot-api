"""
Build-marker tests for the health endpoints.
Run: pytest tests/test_health.py -v

The `build` field on GET / and GET /health lets a deploy be confirmed without
minting a seal: poll until `build` shows the new commit SHA. These tests pin
the two resolution paths — Railway commit SHA, and the local/dev fallback.
"""
import importlib

import app.main as main


def test_health_reports_build(client):
    resp = client.get("/health")
    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] == "ok"
    assert body["build"], "build marker must be present on /health"


def test_root_reports_build(client):
    resp = client.get("/")
    assert resp.status_code == 200
    assert resp.json()["build"], "build marker must be present on /"


def test_build_id_uses_railway_sha(monkeypatch):
    """When Railway injects the commit SHA, build_id reports the short SHA."""
    monkeypatch.setenv("RAILWAY_GIT_COMMIT_SHA", "1943d4c0deadbeef")
    assert main.build_id() == "1943d4c"


def test_build_id_falls_back_to_version(monkeypatch):
    """Outside Railway (no SHA) build_id reports the package version."""
    monkeypatch.delenv("RAILWAY_GIT_COMMIT_SHA", raising=False)
    assert main.build_id() == main.VERSION
"""Health/readiness endpoint tests."""


def test_health_liveness(client):
    r = client.get("/health")
    assert r.status_code == 200
    assert r.json()["status"] == "ok"


def test_healthz_readiness_ok(client):
    """DB reachable (in-memory SQLite) → 200 with db:ok."""
    r = client.get("/healthz")
    assert r.status_code == 200
    body = r.json()
    assert body["status"] == "ok"
    assert body["db"] == "ok"
