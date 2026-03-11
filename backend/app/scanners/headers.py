import httpx
from html.parser import HTMLParser
from urllib.parse import urlparse

from app.scanners.base import BaseScanner, ScanResult, FindingData

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
]

LEAKY_HEADERS = ["server", "x-powered-by", "x-aspnet-version", "x-aspnetmvc-version"]

# Pages susceptibles de poser des cookies de session
COOKIE_PROBE_PATHS = ["/", "/login", "/signin", "/sign-in", "/auth", "/account", "/admin"]


class _SRIParser(HTMLParser):
    """Collecte les ressources externes sans attribut integrity."""

    def __init__(self, origin_host: str) -> None:
        super().__init__()
        self.origin_host = origin_host
        # set de (tag, host) déjà signalés pour dédupliquer par hôte externe
        self.seen: set[tuple[str, str]] = set()
        self.issues: list[tuple[str, str, str]] = []  # (tag, url, host)

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        d = dict(attrs)
        if tag == "script":
            url = d.get("src") or ""
        elif tag == "link" and "stylesheet" in (d.get("rel") or "").lower():
            url = d.get("href") or ""
        else:
            return

        if not url:
            return

        parsed = urlparse(url)
        host = parsed.netloc
        # Ignorer les ressources same-origin et les URLs relatives
        if not host or host == self.origin_host:
            return
        # Ignorer si integrity est présent
        if d.get("integrity"):
            return

        key = (tag, host)
        if key not in self.seen:
            self.seen.add(key)
            self.issues.append((tag, url, host))


class HeadersScanner(BaseScanner):
    name = "headers"
    weight = 0.15

    async def scan(self, domain: str) -> ScanResult:
        findings: list[FindingData] = []
        base_url = f"https://{domain}"

        # verify=False : le scanner TLS gère séparément les problèmes de certificat ;
        # ici on veut analyser les headers et cookies même si le cert est expiré/invalide.
        try:
            async with httpx.AsyncClient(follow_redirects=True, timeout=10, verify=False) as client:
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

        # Subresource Integrity : ressources externes sans attribut integrity
        sri_parser = _SRIParser(domain)
        try:
            sri_parser.feed(response.text)
        except Exception:
            pass
        for tag, url, host in sri_parser.issues:
            findings.append(FindingData(
                severity="medium",
                title=f"SRI manquant sur une ressource externe ({tag})",
                description=f"La ressource chargée depuis '{host}' n'a pas d'attribut integrity.",
                remediation=(
                    f"Ajouter integrity=\"sha384-<hash>\" sur le tag {tag} pointant vers {url}. "
                    "Générer le hash avec : openssl dgst -sha384 -binary fichier.js | openssl base64 -A"
                ),
            ))

        # Analyse des cookies sur plusieurs pages.
        # On sonde les deux schémas pour couvrir deux cas distincts :
        #   - http:// → détecte les cookies posés sur la chaîne de redirection
        #               HTTP→HTTPS (301/302) sans l'attribut Secure
        #   - https:// → détecte les cookies posés directement sur HTTPS sans
        #               Secure (sites qui bloquent le port 80, ou cookies
        #               accessibles en clair si un utilisateur passe en HTTP)
        # Le seen_issues partagé évite les doublons entre les deux passes.
        seen_issues: set[str] = set()
        await _check_cookies(f"http://{domain}", findings, seen_issues)
        await _check_cookies(base_url, findings, seen_issues)

        return ScanResult.from_findings(findings)


async def _check_cookies(base_url: str, findings: list, seen_issues: set[str]) -> None:
    """Probe plusieurs chemins communs et analyse les attributs des Set-Cookie."""
    async with httpx.AsyncClient(follow_redirects=True, timeout=8, verify=False) as client:
        for path in COOKIE_PROBE_PATHS:
            try:
                resp = await client.get(f"{base_url}{path}")
            except Exception:
                continue

            # Inspecter toutes les réponses de la chaîne de redirection,
            # pas uniquement la finale — les cookies de session sont souvent
            # posés sur les 301/302 (ex. HTTP → HTTPS).
            for r in [*resp.history, resp]:
                for raw in r.headers.get_list("set-cookie"):
                    _analyze_cookie(raw, path, seen_issues, findings)


def _analyze_cookie(raw: str, path: str, seen: set, findings: list) -> None:
    """Parse un Set-Cookie brut et vérifie Secure, HttpOnly, SameSite."""
    parts = [p.strip() for p in raw.split(";")]
    if not parts:
        return

    # Le premier élément est name=value
    name = parts[0].split("=")[0].strip() if "=" in parts[0] else parts[0].strip()
    attrs = {p.split("=")[0].strip().lower() for p in parts[1:]}
    attr_map = {}
    for p in parts[1:]:
        k, _, v = p.strip().partition("=")
        attr_map[k.strip().lower()] = v.strip().lower()

    # Secure
    issue_key = f"secure:{name}"
    if "secure" not in attrs and issue_key not in seen:
        seen.add(issue_key)
        findings.append(FindingData(
            severity="medium",
            title=f"Cookie '{name}' sans attribut Secure (trouvé sur {path})",
            description=(
                f"Le cookie '{name}' peut être transmis sur des connexions HTTP non chiffrées."
            ),
            remediation="Ajouter l'attribut Secure à tous les cookies de session.",
        ))

    # HttpOnly
    issue_key = f"httponly:{name}"
    if "httponly" not in attrs and issue_key not in seen:
        seen.add(issue_key)
        findings.append(FindingData(
            severity="medium",
            title=f"Cookie '{name}' sans attribut HttpOnly (trouvé sur {path})",
            description=(
                f"Le cookie '{name}' est accessible via JavaScript, ce qui l'expose aux attaques XSS."
            ),
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
            description=(
                f"Sans SameSite, le cookie '{name}' peut être envoyé dans des requêtes cross-site (CSRF)."
            ),
            remediation="Ajouter SameSite=Strict ou SameSite=Lax selon le besoin.",
        ))
    elif samesite == "none" and "secure" not in attrs and issue_key not in seen:
        seen.add(issue_key)
        findings.append(FindingData(
            severity="high",
            title=f"Cookie '{name}' : SameSite=None sans Secure (trouvé sur {path})",
            description=(
                "SameSite=None exige l'attribut Secure, sinon le cookie est rejeté par les navigateurs modernes."
            ),
            remediation="Ajouter l'attribut Secure ou changer SameSite=Lax.",
        ))
