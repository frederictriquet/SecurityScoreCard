import httpx

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


class HeadersScanner(BaseScanner):
    name = "headers"
    weight = 0.15

    async def scan(self, domain: str) -> ScanResult:
        findings: list[FindingData] = []
        base_url = f"https://{domain}"

        try:
            async with httpx.AsyncClient(follow_redirects=True, timeout=10) as client:
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

        # Analyse des cookies sur plusieurs pages
        await _check_cookies(domain, base_url, client if False else None, findings)

        return ScanResult.from_findings(findings)


async def _check_cookies(domain: str, base_url: str, _unused, findings: list) -> None:
    """Probe plusieurs chemins communs et analyse les attributs des Set-Cookie."""
    seen_issues: set[str] = set()  # évite les doublons si plusieurs pages posent les mêmes cookies

    async with httpx.AsyncClient(follow_redirects=True, timeout=8) as client:
        for path in COOKIE_PROBE_PATHS:
            try:
                resp = await client.get(f"{base_url}{path}")
            except Exception:
                continue

            raw_cookies = resp.headers.get_list("set-cookie")
            for raw in raw_cookies:
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
