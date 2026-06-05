# Scanners Reference

## Common interface

Each scanner inherits from `BaseScanner` and implements `scan(domain)`.
It returns a `ScanResult` with a score (0-100) and a list of findings.

## DNS Scanner (`dns.py`)

**Source**: dnspython via public resolvers (8.8.8.8, 1.1.1.1)
**Weight**: 20%

| Check | Severity if missing/bad |
|--------------|---------------------------|
| SPF record | High |
| DMARC present | High |
| DMARC policy (none/quarantine/reject) | Medium |
| DKIM (heuristic via TXT records) | Medium |
| DNSSEC enabled | Low |
| MX records present | Info |
| Consistent TTLs | Info |

**Scoring**: Deductions per finding based on severity (critical:-30, high:-20, medium:-10, low:-5)

---

## TLS Scanner (`tls.py`)

**Source**: `ssl` stdlib for the handshake, `httpx` for the chain
**Weight**: 20%

| Check | Severity if missing/bad |
|--------------|---------------------------|
| Expired cert | Critical |
| Cert expires in < 30 days | High |
| TLS < 1.2 accepted | High |
| TLS 1.3 supported | Info (bonus) |
| Weak cipher suites (RC4, DES) | High |
| Self-signed certificate | Critical |
| Valid Subject Alternative Names | Medium |

---

## Headers Scanner (`headers.py`)

**Source**: `httpx` HEAD request on `https://{domain}`
**Weight**: 15%

| Header | Severity if missing |
|--------|--------------------|
| `Strict-Transport-Security` | High |
| `Content-Security-Policy` | Medium |
| `X-Frame-Options` | Medium |
| `X-Content-Type-Options` | Low |
| `Referrer-Policy` | Low |
| `Permissions-Policy` | Low |
| `Server` exposed (version) | Info |
| `X-Powered-By` exposed | Info |

---

## Reputation Scanner (`reputation.py`)

**Source**: AbuseIPDB API (free tier: 1000 req/day, API key required)
**Weight**: 20%

Steps:
1. Resolve `domain` → IP(s) via DNS
2. Query AbuseIPDB for each IP
3. Score based on the returned `abuseConfidenceScore`

| abuseConfidenceScore | Severity |
|----------------------|----------|
| > 80 | Critical |
| 50-80 | High |
| 20-50 | Medium |
| 5-20 | Low |
| < 5 | Info |

**Fallback**: if no API key, Spamhaus DNS-based check (free, no API).

---

## Subdomains Scanner (`subdomains.py`)

**Source**: `https://crt.sh/?q=%.{domain}&output=json` (Certificate Transparency)
**Weight**: 10%

- Lists all subdomains found in the CT logs
- Checks whether some subdomains point to abandoned services (dangling DNS)
- Findings = subdomains with a CNAME to nonexistent services (potential subdomain takeover)

---

## Leaks Scanner (`leaks.py`)

**Source**: Have I Been Pwned API v3 (free for domain search)
**Weight**: 15%

Endpoint: `GET https://haveibeenpwned.com/api/v3/breacheddomain/{domain}`

| Number of breaches | Severity |
|--------------------|----------|
| 0 | Info |
| 1-2 | Low |
| 3-5 | Medium |
| 6-10 | High |
| > 10 | Critical |

---

## Adding a scanner

1. Create `backend/app/scanners/myscanner.py` inheriting from `BaseScanner`
2. Implement `scan(self, domain: str) -> ScanResult`
3. Register it in `orchestrator.py` (the `SCANNERS` list)
4. Add its `name` to the `ModuleName` enum in `models.py`
