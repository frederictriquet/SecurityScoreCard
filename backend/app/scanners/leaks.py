import httpx

from app.scanners.base import BaseScanner, ScanResult, FindingData

HIBP_URL = "https://haveibeenpwned.com/api/v3/breacheddomain/{domain}"


class LeaksScanner(BaseScanner):
    name = "leaks"
    weight = 0.15

    async def scan(self, domain: str) -> ScanResult:
        findings: list[FindingData] = []

        try:
            async with httpx.AsyncClient(timeout=15) as client:
                resp = await client.get(
                    HIBP_URL.format(domain=domain),
                    headers={"User-Agent": "SecurityScoreCard/1.0"},
                )

                if resp.status_code == 404:
                    # Aucune breach connue
                    return ScanResult(score=100, findings=[])

                if resp.status_code == 400:
                    findings.append(FindingData(
                        severity="info",
                        title="HIBP : domaine non supporté",
                        description="Have I Been Pwned ne peut pas rechercher ce domaine.",
                    ))
                    return ScanResult.from_findings(findings)

                if resp.status_code != 200:
                    findings.append(FindingData(
                        severity="info",
                        title=f"HIBP : réponse inattendue ({resp.status_code})",
                        description="Impossible de récupérer les données de breach pour ce domaine.",
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

                # Détail des breaches les plus récentes (max 5)
                breach_names = list(data.keys())[:5]
                findings.append(FindingData(
                    severity=sev,
                    title=f"{breach_count} breach(es) connue(s) pour ce domaine (HIBP)",
                    description=(
                        f"Have I Been Pwned recense {breach_count} breach(es) associée(s) au domaine. "
                        f"Exemples : {', '.join(breach_names)}"
                        + (" et d'autres." if breach_count > 5 else ".")
                    ),
                    remediation=(
                        "Informer les utilisateurs concernés, vérifier les mots de passe compromis "
                        "et activer l'authentification multi-facteurs."
                    ),
                ))

        except Exception as exc:
            findings.append(FindingData(
                severity="info",
                title="HIBP : erreur de connexion",
                description=f"Impossible de contacter Have I Been Pwned : {exc}",
            ))

        return ScanResult.from_findings(findings)
