# Architecture - SecurityScoreCard

## Overview

```
┌─────────────────────────────────────────────────────────────────┐
│                        Docker Compose                           │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  ┌──────────┐     ┌──────────────┐     ┌──────────────────┐    │
│  │  Nginx   │────▶│  FastAPI      │────▶│  SQLite (volume) │    │
│  │  :80     │     │  :8000        │     │  /data/ssc.db    │    │
│  └──────────┘     └──────┬───────┘     └──────────────────┘    │
│       │                  │                                      │
│       │           ┌──────▼───────┐                              │
│  SvelteKit        │  Scanners    │──── External sources         │
│  (static build)   │  (async)     │     (DNS, crt.sh, etc.)     │
│                   └──────────────┘                              │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

## Main flow

```
1. User POST /api/scans {domain: "example.com"}
         │
         ▼
2. FastAPI creates a Scan (status=pending) in DB
         │
         ▼
3. BackgroundTask launches ScanOrchestrator
         │
         ├── DNS Scanner ────────▶ result → DB (ScanModule)
         ├── TLS Scanner ────────▶ result → DB (ScanModule)
         ├── Headers Scanner ────▶ result → DB (ScanModule)
         ├── Reputation Scanner ─▶ result → DB (ScanModule)
         ├── Subdomains Scanner ─▶ result → DB (ScanModule)
         └── Leaks Scanner ──────▶ result → DB (ScanModule)
         │
         ▼
4. Compute global score → Scan (status=completed, score=XX)
         │
         ▼
5. Frontend polls GET /api/scans/{id} every 2s
   displays results progressively
```

## Backend components

### API Layer (`routers/`)

| Endpoint | Method | Description |
|----------|---------|-------------|
| `/api/scans` | POST | Launch a scan (body: `{domain}`) |
| `/api/scans` | GET | List recent scans |
| `/api/scans/{id}` | GET | Scan details + modules |
| `/api/scans/{id}` | DELETE | Delete a scan |

### Scan Orchestrator (`scanners/orchestrator.py`)

- Runs all scanners in parallel via `asyncio.gather()`
- Each scanner is independent and writes its results to the DB
- A failing scanner does not prevent the others from running
- Computes the global score at the end

### Scanners (`scanners/`)

Each scanner implements the same interface:

```python
class BaseScanner(ABC):
    name: str           # ex: "dns", "tls"
    weight: float       # weight in the global score (0.0-1.0)

    async def scan(self, domain: str) -> ScanResult:
        """Run the scan and return a structured result."""
        ...
```

| Scanner | Sources | Collected data |
|---------|---------|-------------------|
| `dns.py` | dnspython (public resolver) | SPF, DMARC, DKIM, DNSSEC, MX, NS |
| `tls.py` | ssl stdlib + httpx | TLS version, cert expiration, chain, cipher suites |
| `headers.py` | httpx HEAD | HSTS, CSP, X-Frame-Options, X-Content-Type, Referrer-Policy |
| `reputation.py` | AbuseIPDB free API | IP reputation score, number of reports |
| `subdomains.py` | crt.sh API | List of subdomains via Certificate Transparency |
| `leaks.py` | HIBP API (domain) | Number of breaches associated with the domain |

### Database Layer (`models.py`, `database.py`)

SQLAlchemy async with aiosqlite.

## Frontend components

### Pages

| Route | Component | Description |
|-------|-----------|-------------|
| `/` | `+page.svelte` | Domain input + scan history |
| `/scan/[id]` | `+page.svelte` | Result dashboard with score + per-module details |

### Reusable components

| Component | Role |
|-----------|------|
| `ScoreGauge.svelte` | Circular A-F gauge with color |
| `ModuleCard.svelte` | Module card (name, score, findings) |
| `FindingRow.svelte` | Finding detail row (severity, description) |
| `ScanStatus.svelte` | Status badge (pending/running/completed/failed) |
