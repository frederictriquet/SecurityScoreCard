# SecurityScoreCard — Features & Roadmap

Goal: the most exhaustive passive scan possible, without paid APIs, using open source tools integrated into the Docker backend.

## Legend

- [x] Implemented
- [ ] To implement
- `tool:xxx` — open source tool to integrate into the Docker image

---

## 1. DNS Security

| # | Check | Severity | Status | Notes |
|---|-------|----------|--------|-------|
| 1.1 | SPF — presence and syntax | high | [x] | `dnspython` |
| 1.2 | DMARC — presence and policy (none/quarantine/reject) | high | [x] | `dnspython` |
| 1.3 | DKIM — common selectors | medium | [x] | `dnspython` |
| 1.4 | DNSSEC — signed or not | high | [x] | `dnspython` |
| 1.5 | MX — presence and consistency | medium | [x] | `dnspython` |
| 1.6 | CAA — Certificate Authority Authorization | high | [x] | `dnspython` — check which CAs are authorized |
| 1.7 | MTA-STS — secure email transport policy | high | [x] | `dnspython` — TXT record `_mta-sts.{domain}` |
| 1.8 | TLSA / DANE — mail server authentication | medium | [x] | `dnspython` — `_25._tcp.mx.{domain}` |
| 1.9 | TLS-RPT — TLS Reporting (`_smtp._tls.{domain}`) | low | [x] | `dnspython` |
| 1.10 | BIMI — Brand Indicators for Message Identification | low | [x] | `dnspython` — `default._bimi.{domain}` |
| 1.11 | Zone Transfer (AXFR) — zone transfer test | critical | [x] | `dnspython` — attempt AXFR against the NS |
| 1.12 | Wildcard DNS — wildcard record detection | medium | [x] | Resolve a random subdomain |
| 1.13 | NS redundancy — at least 2 NS on distinct networks | medium | [x] | `dnspython` |
| 1.14 | IDN / Homograph — homograph domain detection | high | [x] | Local Punycode analysis: mixed scripts / confusable characters |

---

## 2. TLS / SSL

| # | Check | Severity | Status | Notes |
|---|-------|----------|--------|-------|
| 2.1 | Expired / not-yet-valid certificate | high | [x] | `ssl` stdlib |
| 2.2 | Self-signed certificate | high | [x] | `ssl` stdlib |
| 2.3 | Supported TLS versions (1.0, 1.1 = bad) | high | [x] | `ssl` stdlib |
| 2.4 | Weak cipher suites (RC4, DES, export) | high | [x] | `ssl` stdlib |
| 2.5 | Incomplete certificate chain | high | [x] | `testssl.sh --server-defaults` |
| 2.6 | Insufficient key size (RSA < 2048, ECC < 256) | high | [x] | `cryptography` — DER parsing |
| 2.7 | Weak signature algorithm (MD5, SHA-1) | high | [x] | `cryptography` — DER parsing |
| 2.8 | OCSP Stapling — support | medium | [x] | `testssl.sh --server-defaults` |
| 2.9 | Certificate Transparency — SCTs present | medium | [x] | `testssl.sh --server-defaults` |
| 2.10 | HSTS Preload — domain in the preload list | medium | [x] | Fetch `https://hstspreload.org/api/v2/status?domain=` |
| 2.11 | Known vulnerabilities: Heartbleed | critical | [x] | `testssl.sh --vulnerabilities` |
| 2.12 | Known vulnerabilities: POODLE | high | [x] | `testssl.sh --vulnerabilities` |
| 2.13 | Known vulnerabilities: ROBOT | high | [x] | `testssl.sh --vulnerabilities` |
| 2.14 | Known vulnerabilities: CRIME/BREACH | high | [x] | `testssl.sh --vulnerabilities` |
| 2.15 | Known vulnerabilities: DROWN | high | [x] | `testssl.sh --vulnerabilities` |
| 2.16 | TLS_FALLBACK_SCSV — downgrade protection | medium | [x] | `testssl.sh --vulnerabilities` |
| 2.17 | Overly broad wildcard certificate | medium | [x] | `cryptography` — wildcard detection in SANs |
| 2.18 | SAN (Subject Alternative Names) — coverage | low | [x] | `cryptography` — verifies domain coverage |

> **`testssl.sh`**: standalone bash tool (~15 MB). Covers checks 2.5 to 2.16 in a single run. Parseable JSON output. Installation: `git clone https://github.com/drwetter/testssl.sh` into the Docker image.

---

## 3. HTTP Headers

| # | Check | Severity | Status | Notes |
|---|-------|----------|--------|-------|
| 3.1 | Strict-Transport-Security (HSTS) | high | [x] | |
| 3.2 | Content-Security-Policy (CSP) | medium | [x] | |
| 3.3 | X-Frame-Options | medium | [x] | |
| 3.4 | X-Content-Type-Options | low | [x] | |
| 3.5 | Referrer-Policy | low | [x] | |
| 3.6 | Permissions-Policy | low | [x] | |
| 3.7 | Cross-Origin-Opener-Policy (COOP) | low | [x] | Protects against cross-origin attacks (Spectre) |
| 3.8 | Cross-Origin-Embedder-Policy (COEP) | low | [x] | Required for `SharedArrayBuffer` |
| 3.9 | Cross-Origin-Resource-Policy (CORP) | low | [x] | Prevents unauthorized cross-origin loading |
| 3.10 | Cache-Control on sensitive pages | medium | [x] | Check `no-store` on `/login`, `/account` |
| 3.11 | X-XSS-Protection (deprecated but flagged if `0`) | low | [x] | Flag if present with value `0` |

---

## 4. Cookies

| # | Check | Severity | Status | Notes |
|---|-------|----------|--------|-------|
| 4.1 | Missing `Secure` attribute | medium | [x] | HTTP + HTTPS probing, redirect chain |
| 4.2 | Missing `HttpOnly` attribute | medium | [x] | |
| 4.3 | Missing `SameSite` attribute or `None` without `Secure` | low–high | [x] | |
| 4.4 | `__Secure-` / `__Host-` prefix not respected | medium | [x] | `__Host-` cookies must have `Secure; Path=/; no Domain` |
| 4.5 | Excessive lifetime (Max-Age > 1 year) | low | [x] | |
| 4.6 | Overly broad scope (`Domain=.example.com`) | medium | [x] | |

---

## 5. Web Content (passive HTML analysis)

| # | Check | Severity | Status | Notes |
|---|-------|----------|--------|-------|
| 5.1 | Missing Subresource Integrity (SRI) | medium | [x] | cross-origin `<script>` and `<link stylesheet>` |
| 5.2 | Mixed Content — HTTP resources on an HTTPS page | high | [x] | `_HTMLSecurityParser` — `<script>`, `<img>`, `<link>`, `<iframe>` |
| 5.3 | Forms submitted over HTTP (`<form action="http://...">`) | high | [x] | `_HTMLSecurityParser` — detects `<form action="http://...">` |
| 5.4 | Permissive CORS (`Access-Control-Allow-Origin: *`) | high | [x] | Sends `Origin: evil.example.com`, checks reflection + credentials |
| 5.5 | Dangerous HTTP methods (PUT, DELETE, TRACE) | medium | [x] | `OPTIONS` request, check `Allow` |
| 5.6 | Information in HTML comments | low | [x] | `_HTMLSecurityParser` — sensitive keywords in `<!-- -->` |

---

## 6. Exposed Files & Information Disclosure

| # | Check | Severity | Status | Notes |
|---|-------|----------|--------|-------|
| 6.1 | `/.git/` — accessible Git repository | critical | [x] | `GET /.git/HEAD` → `ref: ` signature |
| 6.2 | `/.svn/` — accessible SVN repository | critical | [x] | `GET /.svn/entries` + false-positive filter |
| 6.3 | `/.env` — environment variables | critical | [x] | `GET /.env` + HTML content-type filter |
| 6.4 | `web.config` | high | [x] | `GET /web.config` → `<configuration` signature |
| 6.5 | Backup files (`.bak`, `.old`, `.swp`) | high | [x] | `.htpasswd`, `backup.sql`, `dump.sql`, `database.sql` |
| 6.6 | `robots.txt` — exposed sensitive paths | low | [x] | Parse interesting `Disallow` entries (`/admin`, `/api`, `/backup`) |
| 6.7 | `sitemap.xml` — site structure | low | [x] | Check presence |
| 6.8 | `/.well-known/security.txt` | info | [x] | Checks presence + `Contact:` keyword |
| 6.9 | Verbose error pages (stack traces) | medium | [x] | `GET /a-random-404-page`, search for patterns |
| 6.10 | Leaky headers (`Server`, `X-Powered-By`) | info | [x] | |
| 6.11 | Technology detection (CMS, framework) | info | [ ] | `tool:wappalyzer-cli` or regexes on HTML/headers |

---

## 7. Reputation & Threat Intelligence

| # | Check | Severity | Status | Notes |
|---|-------|----------|--------|-------|
| 7.1 | Spamhaus DNSBL | high | [x] | Free fallback |
| 7.2 | AbuseIPDB | medium | [x] | If API key available |
| 7.3 | HIBP (Have I Been Pwned) — domain breaches | high | [x] | API v3 |
| 7.4 | Google Safe Browsing | high | [ ] | Free API (limited quota, free API key) |
| 7.5 | PhishTank | medium | [x] | PhishTank checkurl API; optional `PHISHTANK_API_KEY` (works keyless, lower rate limit); unavailable/not-listed → indeterminate, never penalized |
| 7.6 | URLhaus (abuse.ch) | high | [ ] | Free API — malware URLs |
| 7.7 | VirusTotal | medium | [ ] | Free API (4 req/min) — domain hash |
| 7.8 | SURBL / URIBL lists | medium | [x] | DNS-based, free |

---

## 8. Subdomains & Attack Surface

| # | Check | Severity | Status | Notes |
|---|-------|----------|--------|-------|
| 8.1 | Certificate Transparency (crt.sh) | medium | [x] | |
| 8.2 | Takeover detection | high | [x] | Dangling CNAME heuristics |
| 8.3 | Subdomains with exposed services | medium | [ ] | For each subdomain found, check port 80/443 |
| 8.4 | Exposed internal subdomains | medium | [ ] | Detect `staging.`, `dev.`, `test.`, `internal.` |

---

## 9. Email Security (advanced)

| # | Check | Severity | Status | Notes |
|---|-------|----------|--------|-------|
| 9.1 | STARTTLS on the MX | high | [x] | SMTP connection on port 25, check STARTTLS (port 25 blocked → indeterminate, never a hit) |
| 9.2 | MX TLS certificate | medium | [x] | STARTTLS handshake + chain/hostname/expiry validation (same SMTP connection as 9.1; port 25 blocked → indeterminate) |
| 9.3 | Open relay test | critical | [ ] | Attempt RCPT TO to an external domain (passive) |
| 9.4 | SPF — number of DNS lookups (max 10) | medium | [x] | Count include/a/mx/ptr/exists/redirect mechanisms |
| 9.5 | DKIM — key size (RSA 1024 = weak) | medium | [ ] | Parse the public key from the TXT record |

---

## 10. Network & Ports

| # | Check | Severity | Status | Notes |
|---|-------|----------|--------|-------|
| 10.1 | Common open ports (top 100) | medium | [x] | `nmap -sT --top-ports 100 -T4 --open` |
| 10.2 | Services identified on open ports | medium | [x] | `nmap -sV --version-light` — XML parsing |
| 10.3 | Dangerous ports exposed (3389, 445, 1433, 3306) | high | [x] | 14 dangerous ports detected (FTP, Telnet, SMB, RDP, DB…) |
| 10.4 | WHOIS — registration date, registrar | info | [x] | `python-whois` — alert if domain < 30 days |
| 10.5 | IP geolocation | info | [ ] | Free API (ip-api.com) |

> **`nmap`**: network scanner. Installation in the Docker image: `apt-get install -y nmap`. Run in unprivileged mode (`-sT` connect scan). Parse the XML output (`-oX`).

---

## 11. Open source tools to integrate

| Tool | Main use | Size | Installation |
|-------|----------------|--------|-------------|
| **testssl.sh** | Complete TLS (vulns, ciphers, protocols) | ~15 MB | `git clone` + `apt install openssl procps` |
| **nmap** | Port scanning, service detection | ~25 MB | `apt-get install -y nmap` |
| **wappalyzer-cli** | Web technology detection | ~50 MB | `npm install -g wappalyzer` (optional) |

### Modified backend Dockerfile (example)

```dockerfile
FROM python:3.12-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    curl nmap openssl procps dnsutils \
    && rm -rf /var/lib/apt/lists/*

# testssl.sh
RUN git clone --depth 1 https://github.com/drwetter/testssl.sh /opt/testssl \
    && ln -s /opt/testssl/testssl.sh /usr/local/bin/testssl

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY app/ app/
RUN mkdir -p /data
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
```

---

## 12. Suggested implementation priorities

### Phase 1 — Quick wins (no new tool)

Checks achievable using only Python + `dnspython` + `httpx` + `ssl`:

- [x] 1.6 CAA records
- [x] 1.7 MTA-STS
- [x] 1.8 TLSA / DANE
- [x] 2.6 Key size (`cryptography`)
- [x] 2.7 Signature algorithm (`cryptography`)
- [x] 3.7–3.9 COOP/COEP/CORP headers
- [x] 5.2 Mixed Content
- [x] 5.4 Permissive CORS
- [x] 6.1–6.4 Exposed files (.git, .env, .svn, web.config)
- [x] 6.8 security.txt
- [x] 9.4 SPF lookup count

### Phase 2 — testssl.sh integration

- [x] 2.5 Certificate chain
- [x] 2.8–2.9 OCSP Stapling, CT
- [x] 2.11–2.16 TLS vulnerabilities (Heartbleed, POODLE, ROBOT, CRIME, BREACH, DROWN, LOGJAM, FREAK, BEAST, SWEET32, RC4, CCS, Ticketbleed, FALLBACK_SCSV)

### Phase 3 — Remaining Python checks (no new tool)

- [x] 1.9–1.13 DNS: TLS-RPT, BIMI, AXFR, Wildcard, NS redundancy
- [x] 2.17–2.18 TLS: Wildcard cert, SAN coverage
- [x] 3.10–3.11 Headers: Cache-Control, X-XSS-Protection
- [x] 4.4–4.6 Cookies: Prefixes, Max-Age, Domain scope
- [x] 5.3, 5.5–5.6 Web: HTTP forms, dangerous methods, HTML comments
- [x] 6.5–6.7, 6.9 Files: Backups, robots.txt, sitemap.xml, error pages

### Phase 4 — nmap integration

- [x] 10.1–10.3 Port scanning (top 100, version detection, dangerous ports)

### Phase 5 — Additional free APIs

- [ ] 7.4 Google Safe Browsing
- [x] 7.5 PhishTank
- [ ] 7.6 URLhaus

---

## 13. Product / UX improvements

Beyond raw checks: added value in presentation, tracking, and exploitation of results.

| # | Feature | Status | Notes |
|---|---------|--------|-------|
| 13.1 | Historical comparison | [x] | `GET /api/scans/history?domain=` (sorted history) + `GET /api/scans/{id}/diff` (findings appeared/resolved, score/grade delta). Timeline + diff shown on `routes/scan/[id]` via `ScanHistory.svelte` |
| 13.2 | Export / PDF report | [x] | `frontend/src/lib/exportPdf.js` (jspdf-autotable), used in `routes/scan/[id]/+page.svelte` |
| 13.3 | Actionable remediation | [x] | `remediation` field present in `models.py`/`schemas.py` and populated in all scanners |
| 13.4 | Public API / batch scan | [ ] | Endpoint to scan multiple domains (CI, domain fleet) |
| 13.5 | Scheduled scan + alerting | [ ] | Periodic re-scan of a domain + notification if the score drops |
| 13.6 | Configurable score weighting | [ ] | Scoring profiles (e-commerce, email-focused…) adjusting the weight of categories in the orchestrator |
