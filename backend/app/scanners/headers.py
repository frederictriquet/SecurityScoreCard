from app.scanners.base import BaseScanner, ScanResult


class HeadersScanner(BaseScanner):
    name = "headers"
    weight = 0.15

    async def scan(self, domain: str) -> ScanResult:
        # TODO: Phase 2 — implémenter avec httpx
        # Vérifications : HSTS, CSP, X-Frame-Options, X-Content-Type, Referrer-Policy
        return ScanResult(score=100, findings=[])
