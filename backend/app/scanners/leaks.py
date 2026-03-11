from app.scanners.base import BaseScanner, ScanResult


class LeaksScanner(BaseScanner):
    name = "leaks"
    weight = 0.15

    async def scan(self, domain: str) -> ScanResult:
        # TODO: Phase 2 — implémenter avec Have I Been Pwned API v3
        # GET https://haveibeenpwned.com/api/v3/breacheddomain/{domain}
        return ScanResult(score=100, findings=[])
