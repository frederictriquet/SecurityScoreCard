# SecurityScoreCard — Claude Code Instructions

## Project

Passive security audit tool for web domains. Non-intrusive scans → A-F score with detailed findings.

## Architecture

```
backend/          → FastAPI + SQLAlchemy async + aiosqlite (Python 3.12)
  app/
    main.py       → FastAPI entry point
    models.py     → SQLAlchemy models (Scan, Finding)
    schemas.py    → Pydantic schemas
    database.py   → Async DB config (SQLite /data/security.db)
    limiter.py    → Rate limiting (slowapi)
    routers/      → API routes
    scanners/     → Scan modules (one file per category)
      base.py         → Abstract BaseScanner class
      orchestrator.py → Runs all scanners, computes the score
      dns.py          → SPF, DMARC, DKIM, DNSSEC, MX, CAA, MTA-STS, DANE
      tls.py          → Certificate, TLS versions, ciphers, key, signature
      headers.py      → HTTP headers, cookies, SRI, mixed content, CORS, exposed files
      reputation.py   → AbuseIPDB / Spamhaus
      subdomains.py   → crt.sh, takeover detection
      leaks.py        → HaveIBeenPwned
frontend/         → SvelteKit 5 (static build via adapter-static) + nginx
docker-compose.yml → 2 services: backend + frontend (port 80)
dev.sh            → Helper script (up/down/build/restart/logs/ps)
```

## Conventions

- **Language**: Everything in English — code, comments, and all documentation (`CLAUDE.md`, `README.md`, `docs/`)
- **Web interface**: all user-visible text (frontend AND API messages returned to the frontend) must be in **English**
- **Commits**: Conventional Commits (`feat:`, `fix:`, `docs:`, `refactor:`)
- **Main branch**: `master`
- **CI/CD**: GitHub Actions (ci.yml, release.yml, version.yml, dependabot-automerge.yml)
- **Docker images**: GHCR via release.yml

## Development commands

```bash
# Docker (primary method)
./dev.sh up          # Build + start
./dev.sh logs        # Live logs
./dev.sh down        # Stop

# Local backend
cd backend && python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
uvicorn app.main:app --reload   # http://localhost:8000

# Local frontend
cd frontend && npm install && npm run dev   # http://localhost:5173
```

## Code patterns

### New scanner

Subclass `BaseScanner` in `scanners/base.py`. Each finding is a dict with:
- `check`: check identifier (e.g. `"spf_missing"`)
- `severity`: `"critical"` | `"high"` | `"medium"` | `"low"` | `"info"`
- `title`: short description
- `details`: detailed explanation

The orchestrator (`orchestrator.py`) calls each scanner and aggregates the results.

### Headers scanner

`headers.py` contains several sub-checks: HTTP headers, cookies, SRI, mixed content, CORS, exposed files, leaky headers. It is the largest file — watch out for side effects.

## Environment variables

| Variable | Description | Required |
|----------|-------------|----------|
| `ABUSEIPDB_API_KEY` | AbuseIPDB API key | No (Spamhaus fallback) |
| `PHISHTANK_API_KEY` | PhishTank API key (raises the rate limit) | No (keyless requests work) |

## Roadmap

See `docs/FEATURES.md` for the full list of checks and their implementation status.

## Files to never commit

- `.env` (may contain API keys)
- `*.db` (local SQLite database)
- `__pycache__/`, `.venv/`, `node_modules/`, `.svelte-kit/`, `build/`, `dist/`

## Engineering rules

- Tests must validate real behavior end-to-end (validator→orchestrator→scanner), not isolated internals or mock-only happy paths; avoid tautological string/regex assertions, and never depend on a full production build inside a unit test.
- Don't anchor comments to volatile references (commit hashes, exact UI labels); describe the intent instead, and update or remove any comment whose referent you change in the same edit.
- Any DB schema change (new constraint, index, column) must ship with a migration that works on an existing /data volume — Base.metadata.create_all does not alter existing tables; never rely on operators wiping the database.
- One concern per commit: a behavior change (e.g. validator semantics) must never ride inside an unrelated feature commit, and every commit message must use a conventional type.
