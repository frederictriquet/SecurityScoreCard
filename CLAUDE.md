# SecurityScoreCard — Instructions Claude Code

## Projet

Outil d'audit passif de sécurité pour domaines web. Scans non-intrusifs → score A-F avec détail des findings.

## Architecture

```
backend/          → FastAPI + SQLAlchemy async + aiosqlite (Python 3.12)
  app/
    main.py       → Point d'entrée FastAPI
    models.py     → Modèles SQLAlchemy (Scan, Finding)
    schemas.py    → Schémas Pydantic
    database.py   → Config DB async (SQLite /data/security.db)
    limiter.py    → Rate limiting (slowapi)
    routers/      → Routes API
    scanners/     → Modules de scan (1 fichier par catégorie)
      base.py         → Classe abstraite BaseScanner
      orchestrator.py → Lance tous les scanners, calcule le score
      dns.py          → SPF, DMARC, DKIM, DNSSEC, MX, CAA, MTA-STS, DANE
      tls.py          → Certificat, versions TLS, ciphers, clé, signature
      headers.py      → Headers HTTP, cookies, SRI, mixed content, CORS, fichiers exposés
      reputation.py   → AbuseIPDB / Spamhaus
      subdomains.py   → crt.sh, détection takeover
      leaks.py        → HaveIBeenPwned
frontend/         → SvelteKit 5 (static build via adapter-static) + nginx
docker-compose.yml → 2 services : backend + frontend (port 80)
dev.sh            → Helper script (up/down/build/restart/logs/ps)
```

## Conventions

- **Langue** : Code en anglais, commentaires et docs en français
- **Interface web** : tout le texte visible par l'utilisateur (frontend ET messages d'API renvoyés au frontend) doit être en **anglais**
- **Commits** : Conventional Commits (`feat:`, `fix:`, `docs:`, `refactor:`)
- **Branche principale** : `master`
- **CI/CD** : GitHub Actions (ci.yml, release.yml, version.yml, dependabot-automerge.yml)
- **Images Docker** : GHCR via release.yml

## Commandes de développement

```bash
# Docker (méthode principale)
./dev.sh up          # Build + démarrage
./dev.sh logs        # Logs temps réel
./dev.sh down        # Arrêt

# Backend local
cd backend && python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
uvicorn app.main:app --reload   # http://localhost:8000

# Frontend local
cd frontend && npm install && npm run dev   # http://localhost:5173
```

## Patterns de code

### Nouveau scanner

Hériter de `BaseScanner` dans `scanners/base.py`. Chaque finding est un dict avec :
- `check` : identifiant du check (ex: `"spf_missing"`)
- `severity` : `"critical"` | `"high"` | `"medium"` | `"low"` | `"info"`
- `title` : description courte
- `details` : explication détaillée

L'orchestrateur (`orchestrator.py`) appelle chaque scanner et agrège les résultats.

### Headers scanner

`headers.py` contient plusieurs sous-checks : headers HTTP, cookies, SRI, mixed content, CORS, fichiers exposés, leaky headers. C'est le fichier le plus gros — attention aux effets de bord.

## Variables d'environnement

| Variable | Description | Requis |
|----------|-------------|--------|
| `ABUSEIPDB_API_KEY` | Clé API AbuseIPDB | Non (fallback Spamhaus) |

## Roadmap

Voir `docs/FEATURES.md` pour la liste complète des checks et leur statut d'implémentation.

## Fichiers à ne jamais commit

- `.env` (contient potentiellement des clés API)
- `*.db` (base SQLite locale)
- `__pycache__/`, `.venv/`, `node_modules/`, `.svelte-kit/`, `build/`, `dist/`
