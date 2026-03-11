# Architecture - SecurityScoreCard

## Vue d'ensemble

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
│  SvelteKit        │  Scanners    │──── Sources externes         │
│  (static build)   │  (async)     │     (DNS, crt.sh, etc.)     │
│                   └──────────────┘                              │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

## Flux principal

```
1. User POST /api/scans {domain: "example.com"}
         │
         ▼
2. FastAPI crée un Scan (status=pending) en DB
         │
         ▼
3. BackgroundTask lance ScanOrchestrator
         │
         ├── DNS Scanner ────────▶ résultat → DB (ScanModule)
         ├── TLS Scanner ────────▶ résultat → DB (ScanModule)
         ├── Headers Scanner ────▶ résultat → DB (ScanModule)
         ├── Reputation Scanner ─▶ résultat → DB (ScanModule)
         ├── Subdomains Scanner ─▶ résultat → DB (ScanModule)
         └── Leaks Scanner ──────▶ résultat → DB (ScanModule)
         │
         ▼
4. Calcul du score global → Scan (status=completed, score=XX)
         │
         ▼
5. Frontend poll GET /api/scans/{id} toutes les 2s
   affiche les résultats au fur et à mesure
```

## Composants Backend

### API Layer (`routers/`)

| Endpoint | Méthode | Description |
|----------|---------|-------------|
| `/api/scans` | POST | Lancer un scan (body: `{domain}`) |
| `/api/scans` | GET | Lister les scans récents |
| `/api/scans/{id}` | GET | Détail d'un scan + modules |
| `/api/scans/{id}` | DELETE | Supprimer un scan |

### Scan Orchestrator (`scanners/orchestrator.py`)

- Lance tous les scanners en parallèle via `asyncio.gather()`
- Chaque scanner est indépendant et écrit ses résultats en DB
- Un scanner qui échoue n'empêche pas les autres
- Calcule le score global à la fin

### Scanners (`scanners/`)

Chaque scanner implémente la même interface :

```python
class BaseScanner(ABC):
    name: str           # ex: "dns", "tls"
    weight: float       # poids dans le score global (0.0-1.0)

    async def scan(self, domain: str) -> ScanResult:
        """Exécute le scan et retourne un résultat structuré."""
        ...
```

| Scanner | Sources | Données collectées |
|---------|---------|-------------------|
| `dns.py` | dnspython (résolveur public) | SPF, DMARC, DKIM, DNSSEC, MX, NS |
| `tls.py` | ssl stdlib + httpx | Version TLS, expiration cert, chain, cipher suites |
| `headers.py` | httpx HEAD | HSTS, CSP, X-Frame-Options, X-Content-Type, Referrer-Policy |
| `reputation.py` | AbuseIPDB free API | Score de réputation IP, nombre de reports |
| `subdomains.py` | crt.sh API | Liste des sous-domaines via Certificate Transparency |
| `leaks.py` | HIBP API (domaine) | Nombre de breaches associées au domaine |

### Database Layer (`models.py`, `database.py`)

SQLAlchemy async avec aiosqlite.

## Composants Frontend

### Pages

| Route | Composant | Description |
|-------|-----------|-------------|
| `/` | `+page.svelte` | Input domaine + historique des scans |
| `/scan/[id]` | `+page.svelte` | Dashboard résultat avec score + détail par module |

### Composants réutilisables

| Composant | Rôle |
|-----------|------|
| `ScoreGauge.svelte` | Jauge circulaire A-F avec couleur |
| `ModuleCard.svelte` | Carte d'un module (nom, score, findings) |
| `FindingRow.svelte` | Ligne de détail d'un finding (sévérité, description) |
| `ScanStatus.svelte` | Badge status (pending/running/completed/failed) |
