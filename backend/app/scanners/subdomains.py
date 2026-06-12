import logging

import httpx

from app.scanners.base import BaseScanner, ScanResult, FindingData

logger = logging.getLogger(__name__)

CRT_SH_URL = "https://crt.sh/"

# Common services that an abandoned CNAME may point to
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
                title="No subdomain found in Certificate Transparency",
                description="crt.sh returned no subdomain for this domain.",
            ))
            return ScanResult.from_findings(findings)

        findings.append(FindingData(
            severity="info",
            title=f"{len(subdomains)} subdomain(s) detected via Certificate Transparency",
            description="List: " + ", ".join(sorted(subdomains)[:20])
                + (" (and more...)" if len(subdomains) > 20 else ""),
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
    except (httpx.HTTPError, ValueError) as exc:
        logger.warning("subdomains: crt.sh lookup failed for %s: %s", domain, exc)
        return set()

    if not isinstance(data, list):
        logger.warning(
            "subdomains: unexpected crt.sh payload for %s: %s",
            domain, type(data).__name__,
        )
        return set()

    subdomains: set[str] = set()
    for entry in data:
        name = entry.get("name_value", "")
        for sub in name.splitlines():
            sub = sub.strip().lstrip("*.")
            if sub.endswith(f".{domain}") or sub == domain:
                subdomains.add(sub)
    return subdomains


async def _check_takeover(subdomains: set[str], findings: list) -> None:
    async with httpx.AsyncClient(timeout=5, follow_redirects=True) as client:
        for sub in list(subdomains)[:30]:  # limit the number of requests
            try:
                resp = await client.get(f"https://{sub}")
                if resp.status_code != 404:
                    continue
                # Heuristic detection: final URL points to a known third-party service
                url_str = str(resp.url)
                matched = next(
                    (sig for sig in TAKEOVER_SIGNATURES if sig in url_str),
                    None,
                )
                if matched:
                    findings.append(FindingData(
                        severity="high",
                        title=f"Potential subdomain takeover: {sub}",
                        description=f"The subdomain responds with a 404 from a third-party service ({matched}).",
                        remediation=f"Remove the CNAME for {sub} or claim the resource on the service.",
                    ))
            except httpx.HTTPError as exc:
                logger.debug("subdomains: takeover probe failed for %s: %s", sub, exc)
