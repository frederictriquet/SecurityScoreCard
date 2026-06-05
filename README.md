# SecurityScoreCard

Passive security audit tool for web domains. Runs non-intrusive scans and displays an A–F score with detailed findings.

## Scan Modules

| Module | Checks | Tools |
|--------|--------|-------|
| **DNS Health** | SPF, DMARC, DKIM, DNSSEC, MX, CAA, MTA-STS, DANE, TLS-RPT, BIMI, AXFR, wildcard, NS redundancy | `dnspython` |
| **TLS / SSL** | Certificate validity, chain, TLS versions, ciphers, key size, signature algo, OCSP, CT, vulnerabilities (Heartbleed, POODLE, ROBOT, CRIME…), wildcard cert, SAN coverage | `ssl` stdlib, `cryptography`, `testssl.sh` |
| **HTTP Headers** | HSTS, CSP, X-Frame-Options, X-Content-Type, Referrer-Policy, Permissions-Policy, COOP/COEP/CORP, Cache-Control, X-XSS-Protection | `httpx` |
| **Cookies** | Secure, HttpOnly, SameSite, `__Secure-`/`__Host-` prefixes, Max-Age, Domain scope | `httpx` |
| **Web Content** | SRI, mixed content, insecure forms, CORS, dangerous HTTP methods, HTML comments, exposed files (.git, .env, backups…), robots.txt, error pages, leaky headers | `httpx`, HTML parser |
| **IP Reputation** | AbuseIPDB, Spamhaus DNSBL | API / DNS |
| **Subdomains** | Certificate Transparency (crt.sh), takeover detection | HTTPS / DNS |
| **Leaks (HIBP)** | Data breaches associated with the domain | HaveIBeenPwned API |
| **Ports & WHOIS** | Top 100 ports, dangerous port detection, service identification, WHOIS age/registrar | `nmap`, `python-whois` |

## Stack

- **Backend**: Python 3.12 — FastAPI + SQLAlchemy async + aiosqlite (SQLite)
- **Frontend**: SvelteKit 5 (static build via `adapter-static`) + nginx
- **Infra**: Docker Compose (2 services: backend + frontend)
- **CI/CD**: GitHub Actions → GHCR

## Quick Start

```bash
git clone https://github.com/your-user/SecurityScoreCard.git
cd SecurityScoreCard

# (Optional) Configure environment
cp .env.example .env
# Add ABUSEIPDB_API_KEY if you have one

# Build & start
./dev.sh up
```

The app is available at `http://localhost`.

### dev.sh commands

| Command | Description |
|---------|-------------|
| `./dev.sh up` | Build & start containers |
| `./dev.sh down` | Stop & remove containers |
| `./dev.sh build` | Rebuild images only |
| `./dev.sh restart` | Restart containers |
| `./dev.sh logs` | Tail container logs |
| `./dev.sh ps` | Container status |

## VPS Deployment

### Prerequisites

- Docker + Docker Compose
- Port 80 open

```bash
# Debian/Ubuntu
apt update && apt install -y docker.io docker-compose-plugin
```

### Install & run

```bash
git clone <repo-url> /opt/securityscorecard
cd /opt/securityscorecard
cp .env.example .env
docker compose up -d --build
```

### Update

```bash
cd /opt/securityscorecard
git pull
docker compose up -d --build
```

## Local Development

### Backend

```bash
cd backend
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
uvicorn app.main:app --reload   # http://localhost:8000
```

### Frontend

```bash
cd frontend
npm install
npm run dev   # http://localhost:5173
```

## Environment Variables

| Variable | Description | Required |
|----------|-------------|----------|
| `ABUSEIPDB_API_KEY` | AbuseIPDB API key (free tier) | No — falls back to Spamhaus DNS |

## Architecture

```
backend/
  app/
    main.py            FastAPI entry point
    models.py          SQLAlchemy models (Scan, Finding)
    schemas.py         Pydantic schemas
    database.py        Async SQLite config
    limiter.py         Rate limiting (slowapi)
    routers/           API routes
    scanners/
      base.py          Abstract BaseScanner
      orchestrator.py  Runs all scanners, computes score
      dns.py           13 DNS checks
      tls.py           18 TLS/SSL checks
      headers.py       Headers, cookies, web content, exposed files
      reputation.py    AbuseIPDB / Spamhaus
      subdomains.py    crt.sh, takeover detection
      leaks.py         HaveIBeenPwned
      ports.py         nmap port scan + WHOIS
frontend/
  src/
    routes/            SvelteKit pages
    lib/
      api.js           API client
      components/      Svelte components (ScoreGauge, ModuleCard, FindingRow…)
docker-compose.yml     2 services: backend + frontend
dev.sh                 Helper script
```

## License

MIT
