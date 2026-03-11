# SecurityScoreCard — Features & Roadmap

Objectif : scan passif le plus exhaustif possible, sans API payante, avec des outils open source intégrés au backend Docker.

## Légende

- [x] Implémenté
- [ ] À implémenter
- `tool:xxx` — outil open source à intégrer dans l'image Docker

---

## 1. DNS Security

| # | Check | Sévérité | Status | Notes |
|---|-------|----------|--------|-------|
| 1.1 | SPF — présence et syntaxe | high | [x] | `dnspython` |
| 1.2 | DMARC — présence et policy (none/quarantine/reject) | high | [x] | `dnspython` |
| 1.3 | DKIM — sélecteurs courants | medium | [x] | `dnspython` |
| 1.4 | DNSSEC — signé ou non | high | [x] | `dnspython` |
| 1.5 | MX — présence et cohérence | medium | [x] | `dnspython` |
| 1.6 | CAA — Certificate Authority Authorization | high | [ ] | `dnspython` — vérifier quels CA sont autorisés |
| 1.7 | MTA-STS — policy de transport email sécurisé | high | [ ] | Fetch `https://mta-sts.{domain}/.well-known/mta-sts.txt` |
| 1.8 | TLSA / DANE — authentification des serveurs mail | medium | [ ] | `dnspython` — `_25._tcp.mx.{domain}` |
| 1.9 | TLS-RPT — TLS Reporting (`_smtp._tls.{domain}`) | low | [ ] | `dnspython` |
| 1.10 | BIMI — Brand Indicators for Message Identification | low | [ ] | `dnspython` — `default._bimi.{domain}` |
| 1.11 | Zone Transfer (AXFR) — test de transfert de zone | critical | [ ] | `dnspython` — tenter AXFR sur les NS |
| 1.12 | Wildcard DNS — détection d'enregistrements wildcard | medium | [ ] | Résoudre un sous-domaine aléatoire |
| 1.13 | NS redundancy — au moins 2 NS sur des réseaux distincts | medium | [ ] | `dnspython` |

---

## 2. TLS / SSL

| # | Check | Sévérité | Status | Notes |
|---|-------|----------|--------|-------|
| 2.1 | Certificat expiré / pas encore valide | high | [x] | `ssl` stdlib |
| 2.2 | Certificat auto-signé | high | [x] | `ssl` stdlib |
| 2.3 | Versions TLS supportées (1.0, 1.1 = bad) | high | [x] | `ssl` stdlib |
| 2.4 | Cipher suites faibles (RC4, DES, export) | high | [x] | `ssl` stdlib |
| 2.5 | Chaîne de certificats incomplète | high | [ ] | `tool:testssl.sh` ou `ssl` stdlib |
| 2.6 | Taille de clé insuffisante (RSA < 2048, ECC < 256) | high | [ ] | `ssl` stdlib — `getpeercert()` |
| 2.7 | Algorithme de signature faible (MD5, SHA-1) | high | [ ] | `ssl` stdlib |
| 2.8 | OCSP Stapling — support | medium | [ ] | `tool:testssl.sh` |
| 2.9 | Certificate Transparency — SCT présents | medium | [ ] | `tool:testssl.sh` |
| 2.10 | HSTS Preload — domaine dans la preload list | medium | [ ] | Fetch `https://hstspreload.org/api/v2/status?domain=` |
| 2.11 | Vulnérabilités connues : Heartbleed | critical | [ ] | `tool:testssl.sh --heartbleed` |
| 2.12 | Vulnérabilités connues : POODLE | high | [ ] | `tool:testssl.sh --poodle` |
| 2.13 | Vulnérabilités connues : ROBOT | high | [ ] | `tool:testssl.sh --robot` |
| 2.14 | Vulnérabilités connues : CRIME/BREACH (compression TLS) | high | [ ] | `tool:testssl.sh --crime` |
| 2.15 | Vulnérabilités connues : DROWN | high | [ ] | `tool:testssl.sh --drown` |
| 2.16 | TLS_FALLBACK_SCSV — protection downgrade | medium | [ ] | `tool:testssl.sh --fallback` |
| 2.17 | Certificat wildcard trop large | medium | [ ] | `ssl` stdlib |
| 2.18 | SAN (Subject Alternative Names) — couverture | low | [ ] | `ssl` stdlib |

> **`testssl.sh`** : outil bash standalone (~15 Mo). Couvre les checks 2.5 à 2.16 en une seule exécution. Sortie JSON parseable. Installation : `git clone https://github.com/drwetter/testssl.sh` dans l'image Docker.

---

## 3. HTTP Headers

| # | Check | Sévérité | Status | Notes |
|---|-------|----------|--------|-------|
| 3.1 | Strict-Transport-Security (HSTS) | high | [x] | |
| 3.2 | Content-Security-Policy (CSP) | medium | [x] | |
| 3.3 | X-Frame-Options | medium | [x] | |
| 3.4 | X-Content-Type-Options | low | [x] | |
| 3.5 | Referrer-Policy | low | [x] | |
| 3.6 | Permissions-Policy | low | [x] | |
| 3.7 | Cross-Origin-Opener-Policy (COOP) | medium | [ ] | Protège contre les attaques cross-origin (Spectre) |
| 3.8 | Cross-Origin-Embedder-Policy (COEP) | medium | [ ] | Requis pour `SharedArrayBuffer` |
| 3.9 | Cross-Origin-Resource-Policy (CORP) | medium | [ ] | Empêche le chargement cross-origin non autorisé |
| 3.10 | Cache-Control sur pages sensibles | medium | [ ] | Vérifier `no-store` sur `/login`, `/account` |
| 3.11 | X-XSS-Protection (déprécié mais signalé si `0`) | low | [ ] | Signaler si présent avec valeur `0` |

---

## 4. Cookies

| # | Check | Sévérité | Status | Notes |
|---|-------|----------|--------|-------|
| 4.1 | Attribut `Secure` manquant | medium | [x] | Sondage HTTP + HTTPS, chaîne de redirections |
| 4.2 | Attribut `HttpOnly` manquant | medium | [x] | |
| 4.3 | Attribut `SameSite` manquant ou `None` sans `Secure` | low–high | [x] | |
| 4.4 | Préfixe `__Secure-` / `__Host-` non respecté | medium | [ ] | Cookies `__Host-` doivent avoir `Secure; Path=/; no Domain` |
| 4.5 | Durée de vie excessive (Max-Age > 1 an) | low | [ ] | |
| 4.6 | Scope trop large (`Domain=.example.com`) | medium | [ ] | |

---

## 5. Contenu Web (analyse passive du HTML)

| # | Check | Sévérité | Status | Notes |
|---|-------|----------|--------|-------|
| 5.1 | Subresource Integrity (SRI) manquant | medium | [x] | `<script>` et `<link stylesheet>` cross-origin |
| 5.2 | Mixed Content — ressources HTTP sur page HTTPS | high | [ ] | Parser `<script>`, `<img>`, `<link>`, `<iframe>` src/href HTTP |
| 5.3 | Formulaires soumis en HTTP (`<form action="http://...">`) | high | [ ] | Parser les `<form>` |
| 5.4 | CORS permissif (`Access-Control-Allow-Origin: *`) | high | [ ] | Envoyer `Origin: evil.com`, vérifier la réponse |
| 5.5 | Méthodes HTTP dangereuses (PUT, DELETE, TRACE) | medium | [ ] | Requête `OPTIONS`, vérifier `Allow` |
| 5.6 | Informations dans les commentaires HTML | low | [ ] | Regex sur `<!-- ... -->` pour mots-clés sensibles |

---

## 6. Fichiers exposés & Information Disclosure

| # | Check | Sévérité | Status | Notes |
|---|-------|----------|--------|-------|
| 6.1 | `/.git/` — dépôt Git accessible | critical | [ ] | `GET /.git/HEAD` → 200 = exposé |
| 6.2 | `/.svn/` — dépôt SVN accessible | critical | [ ] | `GET /.svn/entries` |
| 6.3 | `/.env` — variables d'environnement | critical | [ ] | `GET /.env` → 200 |
| 6.4 | `/.htaccess` / `web.config` | high | [ ] | `GET /.htaccess`, `GET /web.config` |
| 6.5 | Fichiers de backup (`.bak`, `.old`, `.swp`) | high | [ ] | Tester sur des paths courants |
| 6.6 | `robots.txt` — chemins sensibles exposés | low | [ ] | Parser les `Disallow` intéressants (`/admin`, `/api`, `/backup`) |
| 6.7 | `sitemap.xml` — structure du site | low | [ ] | Vérifier la présence |
| 6.8 | `/.well-known/security.txt` | info | [ ] | Vérifier la présence (bonne pratique) |
| 6.9 | Pages d'erreur verbeuses (stack traces) | medium | [ ] | `GET /a-random-404-page`, chercher des patterns |
| 6.10 | Leaky headers (`Server`, `X-Powered-By`) | info | [x] | |
| 6.11 | Détection de technologie (CMS, framework) | info | [ ] | `tool:wappalyzer-cli` ou regexes sur HTML/headers |

---

## 7. Réputation & Threat Intelligence

| # | Check | Sévérité | Status | Notes |
|---|-------|----------|--------|-------|
| 7.1 | Spamhaus DNSBL | high | [x] | Fallback gratuit |
| 7.2 | AbuseIPDB | medium | [x] | Si clé API dispo |
| 7.3 | HIBP (Have I Been Pwned) — breaches du domaine | high | [x] | API v3 |
| 7.4 | Google Safe Browsing | high | [ ] | API gratuite (quota limité, clé API gratuite) |
| 7.5 | PhishTank | medium | [ ] | API gratuite — domaine flaggé phishing ? |
| 7.6 | URLhaus (abuse.ch) | high | [ ] | API gratuite — malware URLs |
| 7.7 | VirusTotal | medium | [ ] | API gratuite (4 req/min) — hash de domaine |
| 7.8 | Listes SURBL / URIBL | medium | [ ] | DNS-based, gratuit |

---

## 8. Sous-domaines & Surface d'attaque

| # | Check | Sévérité | Status | Notes |
|---|-------|----------|--------|-------|
| 8.1 | Certificate Transparency (crt.sh) | medium | [x] | |
| 8.2 | Détection de takeover | high | [x] | Heuristiques CNAME dangling |
| 8.3 | Sous-domaines avec services exposés | medium | [ ] | Pour chaque sous-domaine trouvé, check port 80/443 |
| 8.4 | Sous-domaines internes exposés | medium | [ ] | Détecter `staging.`, `dev.`, `test.`, `internal.` |

---

## 9. Email Security (avancé)

| # | Check | Sévérité | Status | Notes |
|---|-------|----------|--------|-------|
| 9.1 | STARTTLS sur les MX | high | [ ] | Connexion SMTP sur port 25, vérifier STARTTLS |
| 9.2 | Certificat TLS des MX | medium | [ ] | Vérifier validité du cert SMTP |
| 9.3 | Open relay test | critical | [ ] | Tenter RCPT TO vers domaine externe (passif) |
| 9.4 | SPF — nombre de lookups DNS (max 10) | medium | [ ] | Compter les includes/redirect récursifs |
| 9.5 | DKIM — taille de clé (RSA 1024 = faible) | medium | [ ] | Parser la clé publique du record TXT |

---

## 10. Réseau & Ports

| # | Check | Sévérité | Status | Notes |
|---|-------|----------|--------|-------|
| 10.1 | Ports ouverts courants (top 100) | medium | [ ] | `tool:nmap` — `nmap -sT --top-ports 100 -T4` |
| 10.2 | Services identifiés sur ports ouverts | medium | [ ] | `tool:nmap` — `-sV` (version detection) |
| 10.3 | Ports dangereux exposés (3389, 445, 1433, 3306) | high | [ ] | `tool:nmap` |
| 10.4 | WHOIS — date d'enregistrement, registrar | info | [ ] | `python-whois` (déjà dans requirements) |
| 10.5 | Géolocalisation IP | info | [ ] | API gratuite (ip-api.com) |

> **`nmap`** : scanner réseau. Installation dans l'image Docker : `apt-get install -y nmap`. Exécution en mode non-privilégié (`-sT` connect scan). Parsing de la sortie XML (`-oX`).

---

## 11. Outils open source à intégrer

| Outil | Usage principal | Taille | Installation |
|-------|----------------|--------|-------------|
| **testssl.sh** | TLS complet (vulns, ciphers, protocoles) | ~15 Mo | `git clone` + `apt install openssl procps` |
| **nmap** | Scan de ports, détection de services | ~25 Mo | `apt-get install -y nmap` |
| **wappalyzer-cli** | Détection de technologies web | ~50 Mo | `npm install -g wappalyzer` (optionnel) |

### Dockerfile backend modifié (exemple)

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

## 12. Priorités d'implémentation suggérées

### Phase 1 — Quick wins (pas de nouvel outil)

Checks faisables uniquement avec Python + `dnspython` + `httpx` + `ssl` :

- [ ] 1.6 CAA records
- [ ] 1.7 MTA-STS
- [ ] 1.8 TLSA / DANE
- [ ] 2.6 Taille de clé
- [ ] 2.7 Algorithme de signature
- [ ] 3.7–3.9 Headers COOP/COEP/CORP
- [ ] 5.2 Mixed Content
- [ ] 5.4 CORS permissif
- [ ] 6.1–6.5 Fichiers exposés (.git, .env, etc.)
- [ ] 6.8 security.txt
- [ ] 9.4 SPF lookup count

### Phase 2 — Intégration de testssl.sh

- [ ] 2.5 Chaîne de certificats
- [ ] 2.8–2.9 OCSP Stapling, CT
- [ ] 2.11–2.16 Vulnérabilités TLS (Heartbleed, POODLE, etc.)

### Phase 3 — Intégration de nmap

- [ ] 10.1–10.3 Scan de ports

### Phase 4 — APIs gratuites additionnelles

- [ ] 7.4 Google Safe Browsing
- [ ] 7.5 PhishTank
- [ ] 7.6 URLhaus
