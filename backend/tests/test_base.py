"""Tests for app.scanners.base — FindingData, ScanResult, BaseScanner."""

import pytest

from app.scanners.base import (
    FindingData,
    ScanResult,
    BaseScanner,
)


# ===================================================================
# FindingData
# ===================================================================


class TestFindingData:
    def test_minimal_creation(self):
        f = FindingData(severity="high", title="Test", description="Desc")
        assert f.severity == "high"
        assert f.title == "Test"
        assert f.description == "Desc"
        assert f.remediation is None
        assert f.raw_data is None

    def test_full_creation(self):
        f = FindingData(
            severity="critical",
            title="Titre",
            description="Description",
            remediation="Fix it",
            raw_data='{"key": "value"}',
        )
        assert f.remediation == "Fix it"
        assert f.raw_data == '{"key": "value"}'


# ===================================================================
# ScanResult
# ===================================================================


class TestScanResult:
    def test_empty_findings_score_100(self):
        result = ScanResult.from_findings([])
        assert result.score == 100
        assert result.findings == []

    def test_single_critical_finding(self):
        findings = [FindingData(severity="critical", title="T", description="D")]
        result = ScanResult.from_findings(findings)
        assert result.score == 70  # 100 - 30

    def test_single_high_finding(self):
        findings = [FindingData(severity="high", title="T", description="D")]
        result = ScanResult.from_findings(findings)
        assert result.score == 80  # 100 - 20

    def test_single_medium_finding(self):
        findings = [FindingData(severity="medium", title="T", description="D")]
        result = ScanResult.from_findings(findings)
        assert result.score == 90  # 100 - 10

    def test_single_low_finding(self):
        findings = [FindingData(severity="low", title="T", description="D")]
        result = ScanResult.from_findings(findings)
        assert result.score == 95  # 100 - 5

    def test_info_finding_no_deduction(self):
        findings = [FindingData(severity="info", title="T", description="D")]
        result = ScanResult.from_findings(findings)
        assert result.score == 100

    def test_multiple_findings_cumulative(self):
        findings = [
            FindingData(severity="critical", title="T1", description="D1"),
            FindingData(severity="high", title="T2", description="D2"),
            FindingData(severity="medium", title="T3", description="D3"),
        ]
        result = ScanResult.from_findings(findings)
        assert result.score == 40  # 100 - 30 - 20 - 10

    def test_score_floors_at_zero(self):
        findings = [
            FindingData(severity="critical", title="T", description="D")
            for _ in range(5)
        ]
        result = ScanResult.from_findings(findings)
        assert result.score == 0  # 100 - 150 → max(0, -50) = 0

    def test_custom_base_score(self):
        findings = [FindingData(severity="high", title="T", description="D")]
        result = ScanResult.from_findings(findings, base_score=50)
        assert result.score == 30  # 50 - 20

    def test_unknown_severity_no_deduction(self):
        findings = [FindingData(severity="unknown", title="T", description="D")]
        result = ScanResult.from_findings(findings)
        assert result.score == 100  # unknown key → SEVERITY_DEDUCTIONS.get() → 0

    def test_findings_preserved_in_result(self):
        findings = [
            FindingData(severity="high", title="A", description="DA"),
            FindingData(severity="low", title="B", description="DB"),
        ]
        result = ScanResult.from_findings(findings)
        assert len(result.findings) == 2
        assert result.findings[0].title == "A"
        assert result.findings[1].title == "B"

    def test_direct_construction(self):
        result = ScanResult(score=42, findings=[])
        assert result.score == 42


# ===================================================================
# BaseScanner (abstraction)
# ===================================================================


class TestBaseScanner:
    def test_cannot_instantiate_directly(self):
        with pytest.raises(TypeError):
            BaseScanner()

    def test_subclass_must_implement_scan(self):
        class Incomplete(BaseScanner):
            name = "incomplete"
            weight = 0.1

        with pytest.raises(TypeError):
            Incomplete()

    def test_valid_subclass(self):
        class Valid(BaseScanner):
            name = "valid"
            weight = 0.1

            async def scan(self, domain: str) -> ScanResult:
                return ScanResult(score=100, findings=[])

        scanner = Valid()
        assert scanner.name == "valid"
        assert scanner.weight == 0.1
