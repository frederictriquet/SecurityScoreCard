import httpx

from app.scanners.base import BaseScanner, ScanResult, FindingData

HIBP_URL = "https://haveibeenpwned.com/api/v3/breacheddomain/{domain}"


class LeaksScanner(BaseScanner):
    name = "leaks"
    weight = 0.10

    async def scan(self, domain: str) -> ScanResult:
        findings: list[FindingData] = []

        try:
            async with httpx.AsyncClient(timeout=15) as client:
                resp = await client.get(
                    HIBP_URL.format(domain=domain),
                    headers={"User-Agent": "SecurityScoreCard/1.0"},
                )

                if resp.status_code == 404:
                    # No known breach
                    return ScanResult(score=100, findings=[])

                if resp.status_code == 400:
                    findings.append(FindingData(
                        severity="info",
                        title="HIBP: unsupported domain",
                        description="Have I Been Pwned cannot search this domain.",
                    ))
                    return ScanResult.from_findings(findings)

                if resp.status_code != 200:
                    findings.append(FindingData(
                        severity="info",
                        title=f"HIBP: unexpected response ({resp.status_code})",
                        description="Unable to retrieve breach data for this domain.",
                    ))
                    return ScanResult.from_findings(findings)

                data: dict = resp.json()
                breach_count = len(data)

                if breach_count == 0:
                    return ScanResult(score=100, findings=[])

                if breach_count > 10:
                    sev = "critical"
                elif breach_count > 5:
                    sev = "high"
                elif breach_count > 2:
                    sev = "medium"
                else:
                    sev = "low"

                # Details of the most recent breaches (max 5)
                breach_names = list(data.keys())[:5]
                findings.append(FindingData(
                    severity=sev,
                    title=f"{breach_count} known breach(es) for this domain (HIBP)",
                    description=(
                        f"Have I Been Pwned lists {breach_count} breach(es) associated with the domain. "
                        f"Examples: {', '.join(breach_names)}"
                        + (" and others." if breach_count > 5 else ".")
                    ),
                    remediation=(
                        "Inform the affected users, check for compromised passwords "
                        "and enable multi-factor authentication."
                    ),
                ))

        except Exception as exc:
            findings.append(FindingData(
                severity="info",
                title="HIBP: connection error",
                description=f"Unable to contact Have I Been Pwned: {exc}",
            ))

        return ScanResult.from_findings(findings)
