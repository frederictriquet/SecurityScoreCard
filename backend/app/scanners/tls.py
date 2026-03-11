from app.scanners.base import BaseScanner, ScanResult


class TlsScanner(BaseScanner):
    name = "tls"
    weight = 0.20

    async def scan(self, domain: str) -> ScanResult:
        # TODO: Phase 2 — implémenter avec ssl stdlib + httpx
        # Vérifications : version TLS, expiration cert, cipher suites, cert auto-signé
        return ScanResult(score=100, findings=[])
