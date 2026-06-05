# Project structure

```
SecurityScoreCard/
│
├── docs/
│   ├── ARCHITECTURE.md     # Overview + flow
│   ├── DATA_MODEL.md       # DB schema + API contracts
│   ├── SCANNERS.md         # Reference for each scanner
│   ├── ROADMAP.md          # Implementation phases
│   └── STRUCTURE.md        # This file
│
├── backend/
│   ├── app/
│   │   ├── main.py                  # FastAPI app + CORS + router mounting
│   │   ├── database.py              # Engine async SQLAlchemy + session
│   │   ├── models.py                # SQLAlchemy models (Scan, ScanModule, Finding)
│   │   ├── schemas.py               # Pydantic schemas (request/response)
│   │   ├── routers/
│   │   │   └── scans.py             # /api/scans endpoints
│   │   └── scanners/
│   │       ├── base.py              # BaseScanner + ScanResult dataclass
│   │       ├── orchestrator.py      # Runs the scanners in parallel
│   │       ├── dns.py
│   │       ├── tls.py
│   │       ├── headers.py
│   │       ├── reputation.py
│   │       ├── subdomains.py
│   │       └── leaks.py
│   ├── requirements.txt
│   └── Dockerfile
│
├── frontend/
│   ├── src/
│   │   ├── routes/
│   │   │   ├── +page.svelte              # Home
│   │   │   └── scan/
│   │   │       └── [id]/
│   │   │           └── +page.svelte      # Result dashboard
│   │   └── lib/
│   │       ├── api.js                    # Fetch helpers
│   │       └── components/
│   │           ├── ScoreGauge.svelte
│   │           ├── ModuleCard.svelte
│   │           ├── FindingRow.svelte
│   │           └── ScanStatus.svelte
│   ├── package.json
│   ├── svelte.config.js
│   └── Dockerfile
│
├── nginx/
│   └── nginx.conf
│
├── docker-compose.yml
└── .env.example              # ABUSEIPDB_API_KEY=, etc.
```
