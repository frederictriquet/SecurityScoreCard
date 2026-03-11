from app.scanners.base import BaseScanner, ScanResult


class ReputationScanner(BaseScanner):
    name = "reputation"
    weight = 0.20

    async def scan(self, domain: str) -> ScanResult:
        # TODO: Phase 2 — implémenter avec AbuseIPDB (API key via env) + fallback Spamhaus DNS
        # Résoudre domain → IPs, vérifier réputation de chaque IP
        return ScanResult(score=100, findings=[])
