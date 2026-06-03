# Roadmap

## Phase 1 — Backend fondations
- [x] Structure du projet backend (FastAPI + SQLAlchemy + aiosqlite)
- [x] Modèles DB (`Scan`, `ScanModule`, `Finding`)
- [x] `BaseScanner` interface abstraite
- [x] Orchestrateur (asyncio.gather)
- [x] Endpoints CRUD scans

## Phase 2 — Scanners
- [x] DNS Scanner (dnspython)
- [x] TLS Scanner (ssl + httpx)
- [x] Headers Scanner (httpx)
- [x] Subdomains Scanner (crt.sh)
- [x] Leaks Scanner (HIBP)
- [x] Reputation Scanner (AbuseIPDB / Spamhaus fallback)

## Phase 3 — Frontend
- [x] Setup SvelteKit
- [x] Page d'accueil (input domaine + liste scans)
- [x] Dashboard résultat (score + modules)
- [x] Composants : ScoreGauge, ModuleCard, FindingRow
- [x] Polling temps réel (résultats au fil du scan)

## Phase 4 — Déploiement
- [x] Dockerfile backend
- [x] Dockerfile frontend (build statique)
- [x] nginx.conf (reverse proxy + static)
- [x] docker-compose.yml
- [x] Variables d'environnement (clés API)

## Phase 5 — Polish
- [x] Gestion des erreurs (domaine invalide, timeout)
- [x] Rate limiting basique
- [ ] Favicon + titres de page (titres OK ; favicon.png manquant — référencé dans `app.html` mais absent de `static/`)
- [x] README déploiement VPS
