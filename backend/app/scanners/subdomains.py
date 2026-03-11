import httpx

from app.scanners.base import BaseScanner, ScanResult, FindingData

CRT_SH_URL = "https://crt.sh/"

# Services courants vers lesquels un CNAME abandonné peut pointer
TAKEOVER_SIGNATURES = [
    "github.io",
    "herokuapp.com",
    "azurewebsites.net",
    "cloudapp.net",
    "fastly.net",
    "pantheon.io",
    "netlify.app",
    "ghost.io",
    "surge.sh",
    "readme.io",
    "helpscoutdocs.com",
]


class SubdomainsScanner(BaseScanner):
    name = "subdomains"
    weight = 0.10

    async def scan(self, domain: str) -> ScanResult:
        findings: list[FindingData] = []

        subdomains = await _fetch_subdomains(domain)

        if not subdomains:
            findings.append(FindingData(
                severity="info",
                title="Aucun sous-domaine trouvé dans Certificate Transparency",
                description="crt.sh n'a retourné aucun sous-domaine pour ce domaine.",
            ))
            return ScanResult.from_findings(findings)

        findings.append(FindingData(
            severity="info",
            title=f"{len(subdomains)} sous-domaine(s) détectés via Certificate Transparency",
            description="Liste : " + ", ".join(sorted(subdomains)[:20])
                + (" (et plus...)" if len(subdomains) > 20 else ""),
        ))

        await _check_takeover(subdomains, findings)

        return ScanResult.from_findings(findings)


async def _fetch_subdomains(domain: str) -> set[str]:
    try:
        async with httpx.AsyncClient(timeout=15) as client:
            resp = await client.get(
                CRT_SH_URL,
                params={"q": f"%.{domain}", "output": "json"},
                headers={"Accept": "application/json"},
            )
            data = resp.json()
            subdomains: set[str] = set()
            for entry in data:
                name = entry.get("name_value", "")
                for sub in name.splitlines():
                    sub = sub.strip().lstrip("*.")
                    if sub.endswith(f".{domain}") or sub == domain:
                        subdomains.add(sub)
            return subdomains
    except Exception:
        return set()


async def _check_takeover(subdomains: set[str], findings: list) -> None:
    async with httpx.AsyncClient(timeout=5, follow_redirects=True) as client:
        for sub in list(subdomains)[:30]:  # limiter les requêtes
            for signature in TAKEOVER_SIGNATURES:
                try:
                    resp = await client.get(f"https://{sub}")
                    # Détection heuristique : réponse 404 d'un service tiers connu
                    if resp.status_code == 404 and any(
                        signature in str(resp.url) for signature in TAKEOVER_SIGNATURES
                    ):
                        findings.append(FindingData(
                            severity="high",
                            title=f"Potentiel subdomain takeover : {sub}",
                            description=f"Le sous-domaine répond avec un 404 d'un service tiers ({signature}).",
                            remediation=f"Supprimer le CNAME de {sub} ou réclamer la ressource sur le service.",
                        ))
                except Exception:
                    pass
