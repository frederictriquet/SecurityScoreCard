# Roadmap

## Phase 1 — Backend fondations
- [ ] Structure du projet backend (FastAPI + SQLAlchemy + aiosqlite)
- [ ] Modèles DB (`Scan`, `ScanModule`, `Finding`)
- [ ] `BaseScanner` interface abstraite
- [ ] Orchestrateur (asyncio.gather)
- [ ] Endpoints CRUD scans

## Phase 2 — Scanners
- [ ] DNS Scanner (dnspython)
- [ ] TLS Scanner (ssl + httpx)
- [ ] Headers Scanner (httpx)
- [ ] Subdomains Scanner (crt.sh)
- [ ] Leaks Scanner (HIBP)
- [ ] Reputation Scanner (AbuseIPDB / Spamhaus fallback)

## Phase 3 — Frontend
- [ ] Setup SvelteKit
- [ ] Page d'accueil (input domaine + liste scans)
- [ ] Dashboard résultat (score + modules)
- [ ] Composants : ScoreGauge, ModuleCard, FindingRow
- [ ] Polling temps réel (résultats au fil du scan)

## Phase 4 — Déploiement
- [ ] Dockerfile backend
- [ ] Dockerfile frontend (build statique)
- [ ] nginx.conf (reverse proxy + static)
- [ ] docker-compose.yml
- [ ] Variables d'environnement (clés API)

## Phase 5 — Polish
- [ ] Gestion des erreurs (domaine invalide, timeout)
- [ ] Rate limiting basique
- [ ] Favicon + titres de page
- [ ] README déploiement VPS
