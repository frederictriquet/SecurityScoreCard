# Roadmap

## Phase 1 — Backend foundations
- [x] Backend project structure (FastAPI + SQLAlchemy + aiosqlite)
- [x] DB models (`Scan`, `ScanModule`, `Finding`)
- [x] Abstract `BaseScanner` interface
- [x] Orchestrator (asyncio.gather)
- [x] Scan CRUD endpoints

## Phase 2 — Scanners
- [x] DNS Scanner (dnspython)
- [x] TLS Scanner (ssl + httpx)
- [x] Headers Scanner (httpx)
- [x] Subdomains Scanner (crt.sh)
- [x] Leaks Scanner (HIBP)
- [x] Reputation Scanner (AbuseIPDB / Spamhaus fallback)

## Phase 3 — Frontend
- [x] SvelteKit setup
- [x] Home page (domain input + scan list)
- [x] Result dashboard (score + modules)
- [x] Components: ScoreGauge, ModuleCard, FindingRow
- [x] Real-time polling (results as the scan progresses)

## Phase 4 — Deployment
- [x] Backend Dockerfile
- [x] Frontend Dockerfile (static build)
- [x] nginx.conf (reverse proxy + static)
- [x] docker-compose.yml
- [x] Environment variables (API keys)

## Phase 5 — Polish
- [x] Error handling (invalid domain, timeout)
- [x] Basic rate limiting
- [x] Favicon + page titles (titles OK; favicon.png missing — referenced in `app.html` but absent from `static/`)
- [x] README VPS deployment
