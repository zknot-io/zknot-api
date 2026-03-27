# ZKNOT Platform API

**Physics enforces. Math proves. You verify.**

FastAPI backend for ZKNOT hardware attestation and chain-of-custody platform.

## Quick start (local)

```bash
# 1. Clone and install
pip install -r requirements.txt

# 2. Set env vars (copy and edit)
cp .env.example .env

# 3. Run (SQLite for local dev — set DATABASE_URL=sqlite:///./zknot.db in .env)
uvicorn app.main:app --reload

# 4. Seed demo data
python -m seed.seed_demo

# 5. Test the widget endpoint
curl http://localhost:8000/v1/verify/ZK-XXXX-XXX
```

API docs auto-generated at: http://localhost:8000/docs

## Key endpoints

| Method | Path | Description |
|--------|------|-------------|
| GET | `/v1/verify/{code}` | Resolve short code or UUID → verified chain entry |
| POST | `/v1/attest` | Ingest signed artifact from Device SDK |
| POST | `/v1/chain/verify` | Walk and verify full chain integrity |
| GET | `/health` | Health check for Railway |

## Railway deployment

1. Push to GitHub
2. New Railway project → Deploy from GitHub repo
3. Add PostgreSQL plugin
4. Set env vars: `DATABASE_URL` (auto-set by Railway), `API_SECRET_KEY`, `CORS_ORIGINS`
5. Add custom domain: `api.zknot.io` → Railway generates SSL automatically

## Website widget swap (10-line JS change)

Find `function runVerify()` in `index.html` and replace the body:

```js
async function runVerify() {
  const code = document.getElementById('verify-input').value.trim();
  if (!code) return;
  setLoading(true);
  try {
    const res = await fetch(`https://api.zknot.io/v1/verify/${encodeURIComponent(code)}`);
    const data = await res.json();
    if (!res.ok) throw new Error(data.detail?.message || 'Not found');
    renderResult({
      short_code: data.short_code,
      artifact_type: data.artifact_type,
      device_id: data.device_id,
      signed_at: data.signed_at,
      chain_position: data.chain_position,
      artifact_hash: data.artifact_hash,   // entry_hash from chain
      verified: data.verified,
      verification_message: data.verification_message,
    });
  } catch (err) {
    renderError(err.message);
  } finally {
    setLoading(false);
  }
}
```

## Patent alignment

- **PAT-001**: Post-nonce enforcement enforced in Device SDK — not this API
- **PAT-004**: ZK-LocalChain — `services/chain.py`, append-only, every entry hashes prev
- **PAT-007**: COMBINED_SESSION artifact type — `POST /v1/attest` with `artifact_type: COMBINED_SESSION`
- **PAT-010**: Short code — `services/crypto.py::derive_short_code()`, deterministic from signature

## Local dev with SQLite

Add to `.env`:
```
DATABASE_URL=sqlite:///./zknot_dev.db
```

And change `database.py` engine creation to:
```python
engine = create_engine(settings.database_url, connect_args={"check_same_thread": False})
```
