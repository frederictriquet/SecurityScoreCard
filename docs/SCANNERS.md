# Référence des Scanners

## Interface commune

Chaque scanner hérite de `BaseScanner` et implémente `scan(domain)`.
Il retourne un `ScanResult` avec un score (0-100) et une liste de findings.

## DNS Scanner (`dns.py`)

**Source** : dnspython via résolveurs publics (8.8.8.8, 1.1.1.1)
**Poids** : 20%

| Vérification | Sévérité si absent/mauvais |
|--------------|---------------------------|
| Enregistrement SPF | High |
| DMARC présent | High |
| DMARC policy (none/quarantine/reject) | Medium |
| DKIM (heuristique via TXT records) | Medium |
| DNSSEC activé | Low |
| MX records présents | Info |
| TTL cohérents | Info |

**Scoring** : Déductions par finding selon sévérité (critical:-30, high:-20, medium:-10, low:-5)

---

## TLS Scanner (`tls.py`)

**Source** : `ssl` stdlib pour le handshake, `httpx` pour la chaîne
**Poids** : 20%

| Vérification | Sévérité si absent/mauvais |
|--------------|---------------------------|
| Cert expiré | Critical |
| Cert expire dans < 30 jours | High |
| TLS < 1.2 accepté | High |
| TLS 1.3 supporté | Info (bonus) |
| Cipher suites faibles (RC4, DES) | High |
| Certificat auto-signé | Critical |
| Subject Alternative Names valides | Medium |

---

## Headers Scanner (`headers.py`)

**Source** : `httpx` requête HEAD sur `https://{domain}`
**Poids** : 15%

| Header | Sévérité si absent |
|--------|--------------------|
| `Strict-Transport-Security` | High |
| `Content-Security-Policy` | Medium |
| `X-Frame-Options` | Medium |
| `X-Content-Type-Options` | Low |
| `Referrer-Policy` | Low |
| `Permissions-Policy` | Low |
| `Server` exposé (version) | Info |
| `X-Powered-By` exposé | Info |

---

## Reputation Scanner (`reputation.py`)

**Source** : AbuseIPDB API (free tier : 1000 req/jour, clé API nécessaire)
**Poids** : 20%

Étapes :
1. Résoudre `domain` → IP(s) via DNS
2. Requête AbuseIPDB pour chaque IP
3. Score basé sur `abuseConfidenceScore` retourné

| abuseConfidenceScore | Sévérité |
|----------------------|----------|
| > 80 | Critical |
| 50-80 | High |
| 20-50 | Medium |
| 5-20 | Low |
| < 5 | Info |

**Fallback** : si pas de clé API, vérification Spamhaus DNS-based (gratuit, pas d'API).

---

## Subdomains Scanner (`subdomains.py`)

**Source** : `https://crt.sh/?q=%.{domain}&output=json` (Certificate Transparency)
**Poids** : 10%

- Liste tous les sous-domaines trouvés dans les logs CT
- Vérifie si certains sous-domaines pointent vers des services abandonnés (dangling DNS)
- Findings = sous-domaines avec CNAME vers services inexistants (subdomain takeover potentiel)

---

## Leaks Scanner (`leaks.py`)

**Source** : Have I Been Pwned API v3 (gratuite pour recherche par domaine)
**Poids** : 15%

Endpoint : `GET https://haveibeenpwned.com/api/v3/breacheddomain/{domain}`

| Nombre de breaches | Sévérité |
|--------------------|----------|
| 0 | Info |
| 1-2 | Low |
| 3-5 | Medium |
| 6-10 | High |
| > 10 | Critical |

---

## Ajout d'un scanner

1. Créer `backend/app/scanners/monscanner.py` héritant de `BaseScanner`
2. Implémenter `scan(self, domain: str) -> ScanResult`
3. L'enregistrer dans `orchestrator.py` (liste `SCANNERS`)
4. Ajouter son `name` à l'enum `ModuleName` dans `models.py`
