# Modèle de données - SecurityScoreCard

## Schéma SQLite

```
┌─────────────────────────────────┐
│            scans                │
├─────────────────────────────────┤
│ id          TEXT (UUID) PK      │
│ domain      TEXT NOT NULL       │
│ status      TEXT (enum)         │
│ score       INTEGER (0-100)     │
│ grade       TEXT (A-F)          │
│ started_at  DATETIME            │
│ completed_at DATETIME           │
│ created_at  DATETIME            │
└────────────────┬────────────────┘
                 │ 1:N
                 ▼
┌─────────────────────────────────┐
│          scan_modules           │
├─────────────────────────────────┤
│ id          TEXT (UUID) PK      │
│ scan_id     TEXT FK → scans.id  │
│ name        TEXT (enum)         │
│ status      TEXT (enum)         │
│ score       INTEGER (0-100)     │
│ weight      REAL                │
│ started_at  DATETIME            │
│ completed_at DATETIME           │
└────────────────┬────────────────┘
                 │ 1:N
                 ▼
┌─────────────────────────────────┐
│           findings              │
├─────────────────────────────────┤
│ id          TEXT (UUID) PK      │
│ module_id   TEXT FK             │
│ severity    TEXT (enum)         │
│ title       TEXT                │
│ description TEXT                │
│ remediation TEXT                │
│ raw_data    TEXT (JSON)         │
└─────────────────────────────────┘
```

## Enums

```
scan.status     : pending | running | completed | failed
scan_module.name: dns | tls | headers | reputation | subdomains | leaks
finding.severity: critical | high | medium | low | info
```

## Calcul du score

```
score_global = Σ (module.score × module.weight) / Σ weights

Poids par module:
  dns        : 0.20
  tls        : 0.20
  headers    : 0.15
  reputation : 0.20
  subdomains : 0.10
  leaks      : 0.15

Grade:
  90-100 → A
  80-89  → B
  70-79  → C
  60-69  → D
  0-59   → F
```

## Contrats API (JSON)

### POST /api/scans
```json
Request:  { "domain": "example.com" }
Response: { "id": "uuid", "domain": "example.com", "status": "pending", "created_at": "..." }
```

### GET /api/scans/{id}
```json
{
  "id": "uuid",
  "domain": "example.com",
  "status": "completed",
  "score": 74,
  "grade": "C",
  "started_at": "...",
  "completed_at": "...",
  "modules": [
    {
      "name": "dns",
      "status": "completed",
      "score": 80,
      "weight": 0.20,
      "findings": [
        {
          "severity": "medium",
          "title": "DMARC policy trop permissive",
          "description": "p=none ne protège pas contre le spoofing",
          "remediation": "Passer à p=quarantine ou p=reject"
        }
      ]
    }
  ]
}
```

### GET /api/scans
```json
[
  { "id": "uuid", "domain": "example.com", "status": "completed", "score": 74, "grade": "C", "created_at": "..." }
]
```
