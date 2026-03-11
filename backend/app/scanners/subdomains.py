from app.scanners.base import BaseScanner, ScanResult


class SubdomainsScanner(BaseScanner):
    name = "subdomains"
    weight = 0.10

    async def scan(self, domain: str) -> ScanResult:
        # TODO: Phase 2 — implémenter avec crt.sh API (Certificate Transparency)
        # Détecter les sous-domaines potentiellement abandonnés (subdomain takeover)
        return ScanResult(score=100, findings=[])
