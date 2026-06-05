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
| 1.6 | CAA — Certificate Authority Authorization | high | [x] | `dnspython` — vérifier quels CA sont autorisés |
| 1.7 | MTA-STS — policy de transport email sécurisé | high | [x] | `dnspython` — record TXT `_mta-sts.{domain}` |
| 1.8 | TLSA / DANE — authentification des serveurs mail | medium | [x] | `dnspython` — `_25._tcp.mx.{domain}` |
| 1.9 | TLS-RPT — TLS Reporting (`_smtp._tls.{domain}`) | low | [x] | `dnspython` |
| 1.10 | BIMI — Brand Indicators for Message Identification | low | [x] | `dnspython` — `default._bimi.{domain}` |
| 1.11 | Zone Transfer (AXFR) — test de transfert de zone | critical | [x] | `dnspython` — tenter AXFR sur les NS |
| 1.12 | Wildcard DNS — détection d'enregistrements wildcard | medium | [x] | Résoudre un sous-domaine aléatoire |
| 1.13 | NS redundancy — au moins 2 NS sur des réseaux distincts | medium | [x] | `dnspython` |
| 1.14 | IDN / Homograph — détection de domaine homographe | high | [x] | Analyse locale du Punycode : scripts mélangés / caractères confusables |

---

## 2. TLS / SSL

| # | Check | Sévérité | Status | Notes |
|---|-------|----------|--------|-------|
| 2.1 | Certificat expiré / pas encore valide | high | [x] | `ssl` stdlib |
| 2.2 | Certificat auto-signé | high | [x] | `ssl` stdlib |
| 2.3 | Versions TLS supportées (1.0, 1.1 = bad) | high | [x] | `ssl` stdlib |
| 2.4 | Cipher suites faibles (RC4, DES, export) | high | [x] | `ssl` stdlib |
| 2.5 | Chaîne de certificats incomplète | high | [x] | `testssl.sh --server-defaults` |
| 2.6 | Taille de clé insuffisante (RSA < 2048, ECC < 256) | high | [x] | `cryptography` — parsing DER |
| 2.7 | Algorithme de signature faible (MD5, SHA-1) | high | [x] | `cryptography` — parsing DER |
| 2.8 | OCSP Stapling — support | medium | [x] | `testssl.sh --server-defaults` |
| 2.9 | Certificate Transparency — SCT présents | medium | [x] | `testssl.sh --server-defaults` |
| 2.10 | HSTS Preload — domaine dans la preload list | medium | [x] | Fetch `https://hstspreload.org/api/v2/status?domain=` |
| 2.11 | Vulnérabilités connues : Heartbleed | critical | [x] | `testssl.sh --vulnerabilities` |
| 2.12 | Vulnérabilités connues : POODLE | high | [x] | `testssl.sh --vulnerabilities` |
| 2.13 | Vulnérabilités connues : ROBOT | high | [x] | `testssl.sh --vulnerabilities` |
| 2.14 | Vulnérabilités connues : CRIME/BREACH | high | [x] | `testssl.sh --vulnerabilities` |
| 2.15 | Vulnérabilités connues : DROWN | high | [x] | `testssl.sh --vulnerabilities` |
| 2.16 | TLS_FALLBACK_SCSV — protection downgrade | medium | [x] | `testssl.sh --vulnerabilities` |
| 2.17 | Certificat wildcard trop large | medium | [x] | `cryptography` — détection wildcards dans SANs |
| 2.18 | SAN (Subject Alternative Names) — couverture | low | [x] | `cryptography` — vérifie couverture du domaine |

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
| 3.7 | Cross-Origin-Opener-Policy (COOP) | low | [x] | Protège contre les attaques cross-origin (Spectre) |
| 3.8 | Cross-Origin-Embedder-Policy (COEP) | low | [x] | Requis pour `SharedArrayBuffer` |
| 3.9 | Cross-Origin-Resource-Policy (CORP) | low | [x] | Empêche le chargement cross-origin non autorisé |
| 3.10 | Cache-Control sur pages sensibles | medium | [x] | Vérifier `no-store` sur `/login`, `/account` |
| 3.11 | X-XSS-Protection (déprécié mais signalé si `0`) | low | [x] | Signaler si présent avec valeur `0` |

---

## 4. Cookies

| # | Check | Sévérité | Status | Notes |
|---|-------|----------|--------|-------|
| 4.1 | Attribut `Secure` manquant | medium | [x] | Sondage HTTP + HTTPS, chaîne de redirections |
| 4.2 | Attribut `HttpOnly` manquant | medium | [x] | |
| 4.3 | Attribut `SameSite` manquant ou `None` sans `Secure` | low–high | [x] | |
| 4.4 | Préfixe `__Secure-` / `__Host-` non respecté | medium | [x] | Cookies `__Host-` doivent avoir `Secure; Path=/; no Domain` |
| 4.5 | Durée de vie excessive (Max-Age > 1 an) | low | [x] | |
| 4.6 | Scope trop large (`Domain=.example.com`) | medium | [x] | |

---

## 5. Contenu Web (analyse passive du HTML)

| # | Check | Sévérité | Status | Notes |
|---|-------|----------|--------|-------|
| 5.1 | Subresource Integrity (SRI) manquant | medium | [x] | `<script>` et `<link stylesheet>` cross-origin |
| 5.2 | Mixed Content — ressources HTTP sur page HTTPS | high | [x] | `_HTMLSecurityParser` — `<script>`, `<img>`, `<link>`, `<iframe>` |
| 5.3 | Formulaires soumis en HTTP (`<form action="http://...">`) | high | [x] | `_HTMLSecurityParser` — détection `<form action="http://...">` |
| 5.4 | CORS permissif (`Access-Control-Allow-Origin: *`) | high | [x] | Envoi `Origin: evil.example.com`, vérif réflexion + credentials |
| 5.5 | Méthodes HTTP dangereuses (PUT, DELETE, TRACE) | medium | [x] | Requête `OPTIONS`, vérifier `Allow` |
| 5.6 | Informations dans les commentaires HTML | low | [x] | `_HTMLSecurityParser` — mots-clés sensibles dans `<!-- -->` |

---

## 6. Fichiers exposés & Information Disclosure

| # | Check | Sévérité | Status | Notes |
|---|-------|----------|--------|-------|
| 6.1 | `/.git/` — dépôt Git accessible | critical | [x] | `GET /.git/HEAD` → signature `ref: ` |
| 6.2 | `/.svn/` — dépôt SVN accessible | critical | [x] | `GET /.svn/entries` + filtre faux positifs |
| 6.3 | `/.env` — variables d'environnement | critical | [x] | `GET /.env` + filtre content-type HTML |
| 6.4 | `web.config` | high | [x] | `GET /web.config` → signature `<configuration` |
| 6.5 | Fichiers de backup (`.bak`, `.old`, `.swp`) | high | [x] | `.htpasswd`, `backup.sql`, `dump.sql`, `database.sql` |
| 6.6 | `robots.txt` — chemins sensibles exposés | low | [x] | Parser les `Disallow` intéressants (`/admin`, `/api`, `/backup`) |
| 6.7 | `sitemap.xml` — structure du site | low | [x] | Vérifier la présence |
| 6.8 | `/.well-known/security.txt` | info | [x] | Vérifie présence + mot-clé `Contact:` |
| 6.9 | Pages d'erreur verbeuses (stack traces) | medium | [x] | `GET /a-random-404-page`, chercher des patterns |
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
| 9.4 | SPF — nombre de lookups DNS (max 10) | medium | [x] | Comptage des mécanismes include/a/mx/ptr/exists/redirect |
| 9.5 | DKIM — taille de clé (RSA 1024 = faible) | medium | [ ] | Parser la clé publique du record TXT |

---

## 10. Réseau & Ports

| # | Check | Sévérité | Status | Notes |
|---|-------|----------|--------|-------|
| 10.1 | Ports ouverts courants (top 100) | medium | [x] | `nmap -sT --top-ports 100 -T4 --open` |
| 10.2 | Services identifiés sur ports ouverts | medium | [x] | `nmap -sV --version-light` — parsing XML |
| 10.3 | Ports dangereux exposés (3389, 445, 1433, 3306) | high | [x] | 14 ports dangereux détectés (FTP, Telnet, SMB, RDP, DB…) |
| 10.4 | WHOIS — date d'enregistrement, registrar | info | [x] | `python-whois` — alerte si domaine < 30 jours |
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

- [x] 1.6 CAA records
- [x] 1.7 MTA-STS
- [x] 1.8 TLSA / DANE
- [x] 2.6 Taille de clé (`cryptography`)
- [x] 2.7 Algorithme de signature (`cryptography`)
- [x] 3.7–3.9 Headers COOP/COEP/CORP
- [x] 5.2 Mixed Content
- [x] 5.4 CORS permissif
- [x] 6.1–6.4 Fichiers exposés (.git, .env, .svn, web.config)
- [x] 6.8 security.txt
- [x] 9.4 SPF lookup count

### Phase 2 — Intégration de testssl.sh

- [x] 2.5 Chaîne de certificats
- [x] 2.8–2.9 OCSP Stapling, CT
- [x] 2.11–2.16 Vulnérabilités TLS (Heartbleed, POODLE, ROBOT, CRIME, BREACH, DROWN, LOGJAM, FREAK, BEAST, SWEET32, RC4, CCS, Ticketbleed, FALLBACK_SCSV)

### Phase 3 — Checks Python restants (pas de nouvel outil)

- [x] 1.9–1.13 DNS : TLS-RPT, BIMI, AXFR, Wildcard, NS redundancy
- [x] 2.17–2.18 TLS : Wildcard cert, SAN coverage
- [x] 3.10–3.11 Headers : Cache-Control, X-XSS-Protection
- [x] 4.4–4.6 Cookies : Préfixes, Max-Age, Domain scope
- [x] 5.3, 5.5–5.6 Web : Forms HTTP, méthodes dangereuses, commentaires HTML
- [x] 6.5–6.7, 6.9 Fichiers : Backups, robots.txt, sitemap.xml, error pages

### Phase 4 — Intégration de nmap

- [x] 10.1–10.3 Scan de ports (top 100, détection de version, ports dangereux)

### Phase 5 — APIs gratuites additionnelles

- [ ] 7.4 Google Safe Browsing
- [ ] 7.5 PhishTank
- [ ] 7.6 URLhaus

---

## 13. Améliorations produit / UX

Au-delà des checks bruts : valeur ajoutée côté présentation, suivi et exploitation des résultats.

| # | Feature | Status | Notes |
|---|---------|--------|-------|
| 13.1 | Comparaison historique | [ ] | Les scans sont déjà persistés (`Scan`, `Finding`). Afficher l'évolution du score d'un domaine dans le temps (régression / amélioration entre 2 scans) |
| 13.2 | Export / rapport PDF | [x] | `frontend/src/lib/exportPdf.js` (jspdf-autotable), utilisé dans `routes/scan/[id]/+page.svelte` |
| 13.3 | Remédiation actionnable | [x] | Champ `remediation` présent dans `models.py`/`schemas.py` et peuplé dans tous les scanners |
| 13.4 | API publique / scan par lot | [ ] | Endpoint pour scanner plusieurs domaines (CI, parc de domaines) |
| 13.5 | Scan programmé + alerting | [ ] | Re-scan périodique d'un domaine + notification si le score chute |
| 13.6 | Pondération configurable du score | [ ] | Profils de scoring (e-commerce, email-focused…) modifiant le poids des catégories dans l'orchestrateur |
