from abc import ABC, abstractmethod
from dataclasses import dataclass, field


SEVERITY_DEDUCTIONS = {
    "critical": 30,
    "high": 20,
    "medium": 10,
    "low": 5,
    "info": 0,
}


@dataclass
class FindingData:
    severity: str  # critical | high | medium | low | info
    title: str
    description: str
    remediation: str | None = None
    raw_data: str | None = None  # JSON string


@dataclass
class ScanResult:
    score: int
    findings: list[FindingData] = field(default_factory=list)

    @classmethod
    def from_findings(cls, findings: list[FindingData], base_score: int = 100) -> "ScanResult":
        score = base_score
        for f in findings:
            score -= SEVERITY_DEDUCTIONS.get(f.severity, 0)
        return cls(score=max(0, score), findings=findings)


class BaseScanner(ABC):
    name: str
    weight: float

    @abstractmethod
    async def scan(self, domain: str) -> ScanResult:
        """Run the passive scan for the given domain."""
        ...
