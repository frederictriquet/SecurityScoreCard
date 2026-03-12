import asyncio

import httpx
from html.parser import HTMLParser
from urllib.parse import urlparse

from app.scanners.base import BaseScanner, ScanResult, FindingData

USER_AGENT = "SecurityScoreCard-Scanner/1.0 (passive security audit)"
_CLIENT_DEFAULTS = {
    "follow_redirects": True,
    "timeout": 10,
    "verify": False,
    "headers": {"User-Agent": USER_AGENT},
}

SECURITY_HEADERS = [
    {
        "name": "strict-transport-security",
        "title": "HSTS manquant",
        "severity": "high",
        "description": "L'en-tête Strict-Transport-Security force HTTPS mais n'est pas présent.",
        "remediation": "Ajouter : Strict-Transport-Security: max-age=31536000; includeSubDomains",
    },
    {
        "name": "content-security-policy",
        "title": "CSP manquant",
        "severity": "medium",
        "description": "L'en-tête Content-Security-Policy protège contre les injections XSS mais n'est pas présent.",
        "remediation": "Définir une politique CSP adaptée à votre application.",
    },
    {
        "name": "x-frame-options",
        "title": "X-Frame-Options manquant",
        "severity": "medium",
        "description": "Sans cet en-tête, la page peut être intégrée dans une iframe (risque de clickjacking).",
        "remediation": "Ajouter : X-Frame-Options: DENY ou SAMEORIGIN",
    },
    {
        "name": "x-content-type-options",
        "title": "X-Content-Type-Options manquant",
        "severity": "low",
        "description": "Sans cet en-tête, le navigateur peut deviner le type MIME (MIME sniffing).",
        "remediation": "Ajouter : X-Content-Type-Options: nosniff",
    },
    {
        "name": "referrer-policy",
        "title": "Referrer-Policy manquant",
        "severity": "low",
        "description": "Sans Referrer-Policy, les URLs complètes peuvent être transmises à des tiers.",
        "remediation": "Ajouter : Referrer-Policy: strict-origin-when-cross-origin",
    },
    {
        "name": "permissions-policy",
        "title": "Permissions-Policy manquant",
        "severity": "low",
        "description": "Sans Permissions-Policy, l'accès aux APIs du navigateur (caméra, micro...) n'est pas restreint.",
        "remediation": "Ajouter un en-tête Permissions-Policy adapté à votre usage.",
    },
    {
        "name": "cross-origin-opener-policy",
        "title": "Cross-Origin-Opener-Policy (COOP) manquant",
        "severity": "low",
        "description": "Sans COOP, la page peut être exploitée via des attaques cross-origin (Spectre, window.opener).",
        "remediation": "Ajouter : Cross-Origin-Opener-Policy: same-origin",
    },
    {
        "name": "cross-origin-embedder-policy",
        "title": "Cross-Origin-Embedder-Policy (COEP) manquant",
        "severity": "low",
        "description": "Sans COEP, la page ne peut pas activer l'isolation cross-origin (SharedArrayBuffer, etc.).",
        "remediation": "Ajouter : Cross-Origin-Embedder-Policy: require-corp",
    },
    {
        "name": "cross-origin-resource-policy",
        "title": "Cross-Origin-Resource-Policy (CORP) manquant",
        "severity": "low",
        "description": "Sans CORP, les ressources peuvent être chargées par n'importe quel site (risque de fuite de données).",
        "remediation": "Ajouter : Cross-Origin-Resource-Policy: same-origin",
    },
]

LEAKY_HEADERS = ["server", "x-powered-by", "x-aspnet-version", "x-aspnetmvc-version"]

# Pages susceptibles de poser des cookies de session
COOKIE_PROBE_PATHS = ["/", "/login", "/signin", "/sign-in", "/auth", "/account", "/admin"]

# Fichiers sensibles dont l'exposition est critique
EXPOSED_FILES = [
    ("/.git/HEAD", "ref: ", "critical",
     "Dépôt Git exposé (.git/)",
     "Le dépôt Git est accessible publiquement. Un attaquant peut télécharger le code source et l'historique.",
     "Bloquer l'accès au dossier .git dans la configuration du serveur web."),
    ("/.env", None, "critical",
     "Fichier .env exposé",
     "Le fichier d'environnement est accessible. Il peut contenir des mots de passe, clés API et secrets.",
     "Bloquer l'accès aux fichiers dotenv et les exclure du déploiement."),
    ("/.svn/entries", None, "critical",
     "Dépôt SVN exposé (.svn/)",
     "Le dépôt Subversion est accessible publiquement.",
     "Bloquer l'accès au dossier .svn."),
    ("/web.config", "<configuration", "high",
     "Fichier web.config exposé",
     "La configuration IIS est accessible et peut contenir des secrets.",
     "Bloquer l'accès au fichier web.config."),
    # Fichiers de backup (6.5)
    ("/.htpasswd", None, "critical",
     "Fichier .htpasswd exposé",
     "Le fichier de mots de passe Apache est accessible publiquement.",
     "Bloquer l'accès aux fichiers .ht* dans la configuration du serveur."),
    ("/backup.sql", None, "critical",
     "Dump SQL accessible (backup.sql)",
     "Un fichier de backup de base de données est exposé. Il peut contenir toutes les données du site.",
     "Supprimer les fichiers de backup du répertoire web public."),
    ("/dump.sql", None, "critical",
     "Dump SQL accessible (dump.sql)",
     "Un fichier de backup de base de données est exposé.",
     "Supprimer les fichiers de backup du répertoire web public."),
    ("/database.sql", None, "critical",
     "Dump SQL accessible (database.sql)",
     "Un fichier de backup de base de données est exposé.",
     "Supprimer les fichiers de backup du répertoire web public."),
]


class _HTMLSecurityParser(HTMLParser):
    """Analyse le HTML pour détecter les problèmes de SRI et de mixed content."""

    def __init__(self, origin_host: str) -> None:
        super().__init__()
        self.origin_host = origin_host
        self.sri_issues: list[tuple[str, str, str]] = []  # (tag, url, host)
        self.mixed_content: list[tuple[str, str]] = []  # (tag, url)
        self.insecure_forms: list[str] = []  # action URLs over HTTP
        self.sensitive_comments: list[tuple[str, str]] = []  # (keyword, excerpt)
        self._seen_sri: set[tuple[str, str]] = set()
        self._seen_mixed: set[str] = set()

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        d = dict(attrs)

        # Déterminer l'URL de la ressource
        url = ""
        if tag == "script":
            url = d.get("src") or ""
        elif tag == "link" and "stylesheet" in (d.get("rel") or "").lower():
            url = d.get("href") or ""

        if url:
            parsed = urlparse(url)
            host = parsed.netloc

            # SRI : ressource cross-origin sans integrity
            if host and host != self.origin_host and not d.get("integrity"):
                key = (tag, host)
                if key not in self._seen_sri:
                    self._seen_sri.add(key)
                    self.sri_issues.append((tag, url, host))

            # Mixed content : ressource HTTP sur page HTTPS
            if parsed.scheme == "http" and host:
                mk = f"{tag}:{host}"
                if mk not in self._seen_mixed:
                    self._seen_mixed.add(mk)
                    self.mixed_content.append((tag, url))

        # Mixed content pour les autres éléments (img, iframe, etc.)
        if tag in ("img", "iframe", "video", "audio", "source", "embed", "object"):
            src = d.get("src") or ""
            if src:
                p = urlparse(src)
                if p.scheme == "http" and p.netloc:
                    mk = f"{tag}:{p.netloc}"
                    if mk not in self._seen_mixed:
                        self._seen_mixed.add(mk)
                        self.mixed_content.append((tag, src))

        # Formulaires soumis en HTTP
        if tag == "form":
            action = d.get("action") or ""
            if action:
                p = urlparse(action)
                if p.scheme == "http" and p.netloc:
                    self.insecure_forms.append(action)

    def handle_comment(self, data: str) -> None:
        _SENSITIVE_KW = [
            "password", "secret", "api_key", "apikey", "api-key", "token",
            "todo", "fixme", "hack", "bug", "debug", "credentials", "private_key",
        ]
        lower = data.lower()
        for kw in _SENSITIVE_KW:
            if kw in lower:
                self.sensitive_comments.append((kw, data.strip()[:120]))
                break


class HeadersScanner(BaseScanner):
    name = "headers"
    weight = 0.15

    async def scan(self, domain: str) -> ScanResult:
        findings: list[FindingData] = []
        base_url = f"https://{domain}"

        # verify=False : le scanner TLS gère séparément les problèmes de certificat ;
        # ici on veut analyser les headers et cookies même si le cert est expiré/invalide.
        try:
            async with httpx.AsyncClient(**_CLIENT_DEFAULTS) as client:
                response = await client.get(base_url)
                headers = {k.lower(): v for k, v in response.headers.items()}
        except Exception as exc:
            findings.append(FindingData(
                severity="high",
                title="Impossible de récupérer les headers HTTP",
                description=f"La requête GET vers {base_url} a échoué : {exc}",
            ))
            return ScanResult.from_findings(findings)

        # Vérification des headers de sécurité
        for check in SECURITY_HEADERS:
            if check["name"] not in headers:
                findings.append(FindingData(
                    severity=check["severity"],
                    title=check["title"],
                    description=check["description"],
                    remediation=check["remediation"],
                ))

        # Headers informatifs exposés
        for header in LEAKY_HEADERS:
            if header in headers:
                findings.append(FindingData(
                    severity="info",
                    title=f"En-tête informatif exposé : {header}",
                    description=f"La valeur '{headers[header]}' révèle des informations sur la stack technique.",
                    remediation=f"Supprimer ou masquer l'en-tête {header}.",
                ))

        # Analyse HTML : SRI + Mixed Content
        parser = _HTMLSecurityParser(domain)
        try:
            parser.feed(response.text)
        except Exception:
            pass

        for tag, url, host in parser.sri_issues:
            findings.append(FindingData(
                severity="medium",
                title=f"SRI manquant sur une ressource externe ({tag})",
                description=f"La ressource chargée depuis '{host}' n'a pas d'attribut integrity.",
                remediation=(
                    f"Ajouter integrity=\"sha384-<hash>\" sur le tag {tag} pointant vers {url}. "
                    "Générer le hash avec : openssl dgst -sha384 -binary fichier.js | openssl base64 -A"
                ),
            ))

        for tag, url in parser.mixed_content:
            findings.append(FindingData(
                severity="high",
                title=f"Mixed content : ressource HTTP ({tag})",
                description=f"La ressource '{url}' est chargée en HTTP sur une page HTTPS, exposant le contenu à l'interception.",
                remediation="Charger toutes les ressources en HTTPS.",
            ))

        for action_url in parser.insecure_forms:
            findings.append(FindingData(
                severity="high",
                title="Formulaire soumis en HTTP",
                description=f"Un formulaire envoie les données vers '{action_url}' en HTTP clair.",
                remediation="Utiliser une URL HTTPS pour l'attribut action du formulaire.",
            ))

        for kw, excerpt in parser.sensitive_comments[:5]:
            findings.append(FindingData(
                severity="low",
                title=f"Commentaire HTML sensible (mot-clé : {kw})",
                description=f"Un commentaire HTML contient '{kw}' : « {excerpt} »",
                remediation="Supprimer les commentaires contenant des informations sensibles avant la mise en production.",
            ))

        # X-XSS-Protection déprécié mais signalé si désactivé
        xss_prot = headers.get("x-xss-protection", "")
        if xss_prot.strip() == "0":
            findings.append(FindingData(
                severity="low",
                title="X-XSS-Protection explicitement désactivé (0)",
                description="L'en-tête X-XSS-Protection est mis à 0, supprimant la protection XSS des anciens navigateurs.",
                remediation="Supprimer l'en-tête ou le configurer à '1; mode=block'.",
            ))

        # Checks parallèles
        await asyncio.gather(
            _check_cors(base_url, findings),
            _check_exposed_files(base_url, findings),
            _check_http_methods(base_url, findings),
            _check_robots_sitemap(base_url, findings),
            _check_cache_control(base_url, findings),
            _check_error_pages(base_url, findings),
        )

        # Cookies (HTTP + HTTPS)
        seen_issues: set[str] = set()
        await _check_cookies(f"http://{domain}", findings, seen_issues)
        await _check_cookies(base_url, findings, seen_issues)

        return ScanResult.from_findings(findings)


# --- Fonctions auxiliaires ---


async def _check_cors(base_url: str, findings: list) -> None:
    """Teste si le serveur reflète un Origin arbitraire ou utilise *."""
    try:
        async with httpx.AsyncClient(**_CLIENT_DEFAULTS) as client:
            resp = await client.get(base_url, headers={"Origin": "https://evil.example.com"})
            acao = resp.headers.get("access-control-allow-origin", "")
            acac = resp.headers.get("access-control-allow-credentials", "").lower()

            if acao == "*":
                findings.append(FindingData(
                    severity="medium",
                    title="CORS trop permissif (Access-Control-Allow-Origin: *)",
                    description="Le serveur autorise les requêtes cross-origin depuis n'importe quel domaine.",
                    remediation="Restreindre Access-Control-Allow-Origin aux domaines autorisés.",
                ))
            elif acao == "https://evil.example.com":
                if acac == "true":
                    findings.append(FindingData(
                        severity="high",
                        title="CORS : réflexion de l'Origin avec credentials",
                        description="Le serveur reflète n'importe quel Origin et autorise les credentials. "
                                    "Cela permet le vol de données cross-origin.",
                        remediation="Ne pas refléter l'Origin sans validation. Maintenir une whitelist.",
                    ))
                else:
                    findings.append(FindingData(
                        severity="medium",
                        title="CORS : réflexion de l'Origin",
                        description="Le serveur reflète n'importe quel Origin dans Access-Control-Allow-Origin.",
                        remediation="Valider l'Origin contre une whitelist avant de le refléter.",
                    ))
    except Exception:
        pass


async def _check_exposed_files(base_url: str, findings: list) -> None:
    """Vérifie l'accessibilité de fichiers sensibles et la présence de security.txt."""
    security_txt_found = False

    async with httpx.AsyncClient(**_CLIENT_DEFAULTS) as client:
        # Baseline 404 pour filtrer les custom 404 qui renvoient 200
        try:
            baseline = await client.get(f"{base_url}/a-path-that-should-not-exist-82719")
            baseline_len = len(baseline.text)
        except Exception:
            baseline_len = -1

        for path, signature, severity, title, desc, remed in EXPOSED_FILES:
            try:
                resp = await client.get(f"{base_url}{path}")
                if resp.status_code != 200:
                    continue

                text = resp.text[:2000]
                content_type = resp.headers.get("content-type", "")

                # Filtrer les custom 404 (même taille que la baseline)
                if baseline_len > 0 and abs(len(resp.text) - baseline_len) < 100:
                    continue

                # Si signature requise, vérifier sa présence
                if signature and signature not in text:
                    continue

                # Sans signature, ignorer les réponses HTML (probablement une page d'erreur)
                if not signature and "text/html" in content_type:
                    continue

                findings.append(FindingData(
                    severity=severity,
                    title=title,
                    description=desc,
                    remediation=remed,
                ))
            except Exception:
                continue

        # security.txt
        try:
            resp = await client.get(f"{base_url}/.well-known/security.txt")
            if resp.status_code == 200 and "contact:" in resp.text.lower():
                security_txt_found = True
        except Exception:
            pass

    if not security_txt_found:
        findings.append(FindingData(
            severity="info",
            title="security.txt absent",
            description="Aucun fichier security.txt trouvé. Ce fichier aide les chercheurs en sécurité à signaler les vulnérabilités.",
            remediation="Créer /.well-known/security.txt selon le RFC 9116 (Contact, Expires, etc.).",
        ))


async def _check_cookies(base_url: str, findings: list, seen_issues: set[str]) -> None:
    """Probe plusieurs chemins communs et analyse les attributs des Set-Cookie."""
    async with httpx.AsyncClient(**_CLIENT_DEFAULTS) as client:
        for path in COOKIE_PROBE_PATHS:
            try:
                resp = await client.get(f"{base_url}{path}")
            except Exception:
                continue

            for r in [*resp.history, resp]:
                for raw in r.headers.get_list("set-cookie"):
                    _analyze_cookie(raw, path, seen_issues, findings)


def _analyze_cookie(raw: str, path: str, seen: set, findings: list) -> None:
    """Parse un Set-Cookie brut et vérifie Secure, HttpOnly, SameSite."""
    parts = [p.strip() for p in raw.split(";")]
    if not parts:
        return

    name = parts[0].split("=")[0].strip() if "=" in parts[0] else parts[0].strip()
    attrs = {p.split("=")[0].strip().lower() for p in parts[1:]}
    attr_map = {}
    for p in parts[1:]:
        k, _, v = p.strip().partition("=")
        attr_map[k.strip().lower()] = v.strip().lower()

    # Préfixe __Secure- (4.4)
    if name.startswith("__Secure-") and "secure" not in attrs:
        issue_key = f"prefix-secure:{name}"
        if issue_key not in seen:
            seen.add(issue_key)
            findings.append(FindingData(
                severity="medium",
                title=f"Cookie '{name}' : préfixe __Secure- sans attribut Secure",
                description="Les cookies avec le préfixe __Secure- doivent impérativement avoir l'attribut Secure.",
                remediation="Ajouter l'attribut Secure ou retirer le préfixe __Secure-.",
            ))

    # Préfixe __Host- (4.4)
    if name.startswith("__Host-"):
        problems = []
        if "secure" not in attrs:
            problems.append("Secure manquant")
        if attr_map.get("path", "") != "/":
            problems.append("Path doit être /")
        if "domain" in attr_map:
            problems.append("Domain ne doit pas être défini")
        if problems:
            issue_key = f"prefix-host:{name}"
            if issue_key not in seen:
                seen.add(issue_key)
                findings.append(FindingData(
                    severity="medium",
                    title=f"Cookie '{name}' : préfixe __Host- mal configuré",
                    description=f"Problèmes : {', '.join(problems)}. Les cookies __Host- exigent Secure, Path=/ et aucun Domain.",
                    remediation="Corriger les attributs du cookie selon les exigences du préfixe __Host-.",
                ))

    # Max-Age excessif > 1 an (4.5)
    max_age_str = attr_map.get("max-age", "")
    if max_age_str:
        try:
            max_age = int(max_age_str)
            if max_age > 31536000:
                issue_key = f"maxage:{name}"
                if issue_key not in seen:
                    seen.add(issue_key)
                    days = max_age // 86400
                    findings.append(FindingData(
                        severity="low",
                        title=f"Cookie '{name}' : durée de vie excessive ({days} jours)",
                        description=f"Le cookie a un Max-Age de {days} jours (> 1 an), augmentant la fenêtre d'exploitation en cas de vol.",
                        remediation="Réduire la durée de vie des cookies de session à quelques heures ou jours.",
                    ))
        except ValueError:
            pass

    # Scope trop large (4.6)
    cookie_domain = attr_map.get("domain", "")
    if cookie_domain and cookie_domain.startswith("."):
        issue_key = f"domain-scope:{name}"
        if issue_key not in seen:
            seen.add(issue_key)
            findings.append(FindingData(
                severity="medium",
                title=f"Cookie '{name}' : scope trop large (Domain={cookie_domain})",
                description=f"Le cookie est partagé avec tous les sous-domaines de {cookie_domain}. Un sous-domaine compromis peut y accéder.",
                remediation="Retirer l'attribut Domain ou le restreindre au sous-domaine nécessaire.",
            ))

    # Secure
    issue_key = f"secure:{name}"
    if "secure" not in attrs and issue_key not in seen:
        seen.add(issue_key)
        findings.append(FindingData(
            severity="medium",
            title=f"Cookie '{name}' sans attribut Secure (trouvé sur {path})",
            description=f"Le cookie '{name}' peut être transmis sur des connexions HTTP non chiffrées.",
            remediation="Ajouter l'attribut Secure à tous les cookies de session.",
        ))

    # HttpOnly
    issue_key = f"httponly:{name}"
    if "httponly" not in attrs and issue_key not in seen:
        seen.add(issue_key)
        findings.append(FindingData(
            severity="medium",
            title=f"Cookie '{name}' sans attribut HttpOnly (trouvé sur {path})",
            description=f"Le cookie '{name}' est accessible via JavaScript, ce qui l'expose aux attaques XSS.",
            remediation="Ajouter l'attribut HttpOnly à tous les cookies de session.",
        ))

    # SameSite
    issue_key = f"samesite:{name}"
    samesite = attr_map.get("samesite", "")
    if not samesite and issue_key not in seen:
        seen.add(issue_key)
        findings.append(FindingData(
            severity="low",
            title=f"Cookie '{name}' sans attribut SameSite (trouvé sur {path})",
            description=f"Sans SameSite, le cookie '{name}' peut être envoyé dans des requêtes cross-site (CSRF).",
            remediation="Ajouter SameSite=Strict ou SameSite=Lax selon le besoin.",
        ))
    elif samesite == "none" and "secure" not in attrs and issue_key not in seen:
        seen.add(issue_key)
        findings.append(FindingData(
            severity="high",
            title=f"Cookie '{name}' : SameSite=None sans Secure (trouvé sur {path})",
            description="SameSite=None exige l'attribut Secure, sinon le cookie est rejeté par les navigateurs modernes.",
            remediation="Ajouter l'attribut Secure ou changer SameSite=Lax.",
        ))


# --- Phase 3 : nouveaux checks ---


async def _check_http_methods(base_url: str, findings: list) -> None:
    """Vérifie si des méthodes HTTP dangereuses sont autorisées (OPTIONS)."""
    try:
        async with httpx.AsyncClient(**_CLIENT_DEFAULTS) as client:
            resp = await client.options(base_url)
            allow = resp.headers.get("allow", "")
            if not allow:
                return
            methods = {m.strip().upper() for m in allow.split(",")}
            dangerous = methods & {"PUT", "DELETE", "TRACE", "CONNECT"}
            if dangerous:
                findings.append(FindingData(
                    severity="medium",
                    title=f"Méthodes HTTP dangereuses autorisées : {', '.join(sorted(dangerous))}",
                    description=f"Le serveur autorise {', '.join(sorted(dangerous))} via l'en-tête Allow.",
                    remediation="Désactiver les méthodes HTTP non nécessaires dans la configuration du serveur.",
                ))
    except Exception:
        pass


async def _check_robots_sitemap(base_url: str, findings: list) -> None:
    """Analyse robots.txt et vérifie sitemap.xml."""
    async with httpx.AsyncClient(**_CLIENT_DEFAULTS) as client:
        # robots.txt
        try:
            resp = await client.get(f"{base_url}/robots.txt")
            if resp.status_code == 200 and "disallow" in resp.text.lower():
                sensitive = [
                    "admin", "api", "backup", "config", "dashboard", "debug",
                    "internal", "private", "secret", "staging", "test", "deploy",
                ]
                exposed = []
                for line in resp.text.splitlines():
                    low = line.strip().lower()
                    if low.startswith("disallow:"):
                        path = low.split(":", 1)[1].strip()
                        for kw in sensitive:
                            if kw in path:
                                exposed.append(line.strip().split(":", 1)[1].strip())
                                break
                if exposed:
                    findings.append(FindingData(
                        severity="low",
                        title="robots.txt révèle des chemins sensibles",
                        description=f"Chemins potentiellement sensibles listés dans robots.txt : {', '.join(exposed[:5])}",
                        remediation="Vérifier que ces chemins ne sont pas accessibles sans authentification.",
                    ))
        except Exception:
            pass

        # sitemap.xml
        try:
            resp = await client.get(f"{base_url}/sitemap.xml")
            if resp.status_code == 200 and ("<?xml" in resp.text[:200] or "<urlset" in resp.text[:500]):
                findings.append(FindingData(
                    severity="info",
                    title="sitemap.xml accessible",
                    description="Le fichier sitemap.xml est publiquement accessible et révèle la structure du site.",
                    remediation="Vérifier que le sitemap ne référence pas de pages internes ou protégées.",
                ))
        except Exception:
            pass


async def _check_cache_control(base_url: str, findings: list) -> None:
    """Vérifie Cache-Control sur les pages sensibles (login, account...)."""
    sensitive_paths = ["/login", "/signin", "/account", "/admin", "/dashboard"]
    async with httpx.AsyncClient(**_CLIENT_DEFAULTS) as client:
        for path in sensitive_paths:
            try:
                resp = await client.get(f"{base_url}{path}")
                if resp.status_code != 200:
                    continue
                cc = resp.headers.get("cache-control", "").lower()
                if "no-store" not in cc and "no-cache" not in cc:
                    findings.append(FindingData(
                        severity="medium",
                        title=f"Cache-Control manquant sur page sensible ({path})",
                        description=f"La page {path} ne contient pas 'no-store' dans Cache-Control. Elle pourrait être mise en cache.",
                        remediation="Ajouter Cache-Control: no-store, no-cache sur les pages d'authentification et sensibles.",
                    ))
                    return  # Un seul finding suffit
            except Exception:
                continue


async def _check_error_pages(base_url: str, findings: list) -> None:
    """Vérifie si les pages d'erreur exposent des stack traces."""
    try:
        async with httpx.AsyncClient(**_CLIENT_DEFAULTS) as client:
            resp = await client.get(f"{base_url}/a-nonexistent-page-security-test-73921")
            if resp.status_code < 400:
                return
            text = resp.text[:5000].lower()
            leak_patterns = [
                "traceback", "exception", "stack trace", "at java.", "at com.",
                "at org.", "at net.", "fatal error", "syntax error", "parse error",
                "sqlstate", "mysql_", "pg_query", "microsoft ole db",
            ]
            for pattern in leak_patterns:
                if pattern in text:
                    findings.append(FindingData(
                        severity="medium",
                        title="Page d'erreur verbeuse (informations techniques exposées)",
                        description=f"La page d'erreur contient '{pattern}', révélant des détails techniques utiles à un attaquant.",
                        remediation="Configurer des pages d'erreur personnalisées sans détails techniques en production.",
                    ))
                    return
    except Exception:
        pass
