from app.scanners.base import BaseScanner, ScanResult, FindingData


class DnsScanner(BaseScanner):
    name = "dns"
    weight = 0.20

    async def scan(self, domain: str) -> ScanResult:
        # TODO: Phase 2 — implémenter avec dnspython
        # Vérifications : SPF, DMARC, DKIM, DNSSEC, MX, TTL
        return ScanResult(score=100, findings=[])
