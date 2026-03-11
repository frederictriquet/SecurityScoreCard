# SecurityScoreCard

Outil d'audit passif de sécurité pour domaines. Lance des scans non-intrusifs et affiche un score A-F avec le détail des findings.

## Modules de scan

| Module | Sources | Vérifications |
|--------|---------|---------------|
| DNS Health | dnspython | SPF, DMARC, DKIM, DNSSEC, MX |
| TLS / SSL | ssl stdlib | Expiration, version, cipher suites, auto-signé |
| HTTP Headers | httpx | HSTS, CSP, X-Frame-Options, X-Content-Type, Referrer-Policy |
| IP Réputation | AbuseIPDB / Spamhaus | Score d'abus, listes noires |
| Sous-domaines | crt.sh (CT logs) | Enumération, détection takeover |
| Fuites (HIBP) | HaveIBeenPwned | Breaches associées au domaine |

## Stack

- **Backend** : FastAPI + SQLAlchemy async + aiosqlite (SQLite)
- **Frontend** : SvelteKit (static build) + nginx
- **Infra** : Docker Compose

---

## Déploiement VPS

### Prérequis

- Docker + Docker Compose installés
- Port 80 ouvert

```bash
# Sur Debian/Ubuntu
apt update && apt install -y docker.io docker-compose-plugin
```

### Installation

```bash
git clone <url-du-repo> /opt/securityscorecard
cd /opt/securityscorecard

# Configurer les variables d'environnement
cp .env.example .env
# Optionnel : ajouter une clé AbuseIPDB pour le scanner de réputation
# nano .env

# Lancer
docker compose up -d --build
```

L'application est disponible sur `http://<ip-du-vps>`.

### Mise à jour

```bash
cd /opt/securityscorecard
git pull
docker compose up -d --build
```

### Logs

```bash
docker compose logs -f backend
docker compose logs -f frontend
```

### Arrêt

```bash
docker compose down
# Les données SQLite sont préservées dans le volume Docker db_data
```

---

## Développement local

### Backend

```bash
cd backend
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
mkdir -p /data
uvicorn app.main:app --reload
# API disponible sur http://localhost:8000
```

### Frontend

```bash
cd frontend
npm install
npm run dev
# UI disponible sur http://localhost:5173
```

### Variables d'environnement

| Variable | Description | Requis |
|----------|-------------|--------|
| `ABUSEIPDB_API_KEY` | Clé API AbuseIPDB (free tier) | Non — fallback Spamhaus si absent |

Sans clé AbuseIPDB, le scanner de réputation utilise Spamhaus via DNS (gratuit, pas d'inscription requise).
