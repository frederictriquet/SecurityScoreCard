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


class HeadersScanner(BaseScanner):
    name = "headers"
    weight = 0.15

    async def scan(self, domain: str) -> ScanResult:
        findings: list[FindingData] = []
        url = f"https://{domain}"

        try:
            async with httpx.AsyncClient(follow_redirects=True, timeout=10) as client:
                response = await client.head(url)
                headers = {k.lower(): v for k, v in response.headers.items()}
        except Exception as exc:
            findings.append(FindingData(
                severity="high",
                title="Impossible de récupérer les headers HTTP",
                description=f"La requête HEAD vers {url} a échoué : {exc}",
            ))
            return ScanResult.from_findings(findings)

        for check in SECURITY_HEADERS:
            if check["name"] not in headers:
                findings.append(FindingData(
                    severity=check["severity"],
                    title=check["title"],
                    description=check["description"],
                    remediation=check["remediation"],
                ))

        for header in LEAKY_HEADERS:
            if header in headers:
                value = headers[header]
                findings.append(FindingData(
                    severity="info",
                    title=f"En-tête informatif exposé : {header}",
                    description=f"La valeur '{value}' révèle des informations sur la stack technique.",
                    remediation=f"Supprimer ou masquer l'en-tête {header}.",
                ))

        return ScanResult.from_findings(findings)
