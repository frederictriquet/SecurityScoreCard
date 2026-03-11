# Structure du projet

```
SecurityScoreCard/
│
├── docs/
│   ├── ARCHITECTURE.md     # Vue d'ensemble + flux
│   ├── DATA_MODEL.md       # Schéma DB + contrats API
│   ├── SCANNERS.md         # Référence de chaque scanner
│   ├── ROADMAP.md          # Phases d'implémentation
│   └── STRUCTURE.md        # Ce fichier
│
├── backend/
│   ├── app/
│   │   ├── main.py                  # FastAPI app + CORS + montage routeurs
│   │   ├── database.py              # Engine async SQLAlchemy + session
│   │   ├── models.py                # SQLAlchemy models (Scan, ScanModule, Finding)
│   │   ├── schemas.py               # Pydantic schemas (request/response)
│   │   ├── routers/
│   │   │   └── scans.py             # Endpoints /api/scans
│   │   └── scanners/
│   │       ├── base.py              # BaseScanner + ScanResult dataclass
│   │       ├── orchestrator.py      # Lance les scanners en parallèle
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
│   │   │   ├── +page.svelte              # Accueil
│   │   │   └── scan/
│   │   │       └── [id]/
│   │   │           └── +page.svelte      # Dashboard résultat
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
