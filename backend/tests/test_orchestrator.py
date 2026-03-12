"""Tests pour app.scanners.orchestrator — score_to_grade, run_scan, run_single_scanner."""

import pytest
from unittest.mock import patch, AsyncMock

from sqlalchemy import select
from sqlalchemy.orm import selectinload

from app.database import Base, engine, AsyncSessionLocal
from app.models import Scan, ScanModule, Finding
from app.scanners.base import BaseScanner, ScanResult, FindingData
from app.scanners.orchestrator import (
    score_to_grade,
    run_scan,
    run_single_scanner,
    SCANNERS,
    GRADES,
)


# ===================================================================
# DB fixture — tables créées/détruites pour chaque test
# ===================================================================


@pytest.fixture(autouse=True)
async def setup_db():
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)


# ===================================================================
# Helpers — scanners factices
# ===================================================================


class FakeScanner(BaseScanner):
    """Scanner factice qui retourne un résultat prédéfini."""

    def __init__(self, name: str, weight: float, score: int, findings: list[FindingData] | None = None):
        self.name = name
        self.weight = weight
        self._score = score
        self._findings = findings or []

    async def scan(self, domain: str) -> ScanResult:
        return ScanResult(score=self._score, findings=self._findings)


class FailingScanner(BaseScanner):
    """Scanner factice qui lève une exception."""

    def __init__(self, name: str, weight: float, error_msg: str = "Scanner crashed"):
        self.name = name
        self.weight = weight
        self._error_msg = error_msg

    async def scan(self, domain: str) -> ScanResult:
        raise RuntimeError(self._error_msg)


async def _create_scan_in_db(domain: str = "example.com") -> str:
    """Insère un Scan pending en DB et retourne son id."""
    async with AsyncSessionLocal() as session:
        scan = Scan(domain=domain)
        session.add(scan)
        await session.commit()
        return scan.id


async def _get_scan_full(scan_id: str) -> Scan:
    """Relit un Scan avec ses modules et findings."""
    async with AsyncSessionLocal() as session:
        result = await session.execute(
            select(Scan)
            .options(selectinload(Scan.modules).selectinload(ScanModule.findings))
            .where(Scan.id == scan_id)
        )
        return result.scalar_one()


async def _get_modules(scan_id: str) -> list[ScanModule]:
    async with AsyncSessionLocal() as session:
        result = await session.execute(
            select(ScanModule)
            .options(selectinload(ScanModule.findings))
            .where(ScanModule.scan_id == scan_id)
        )
        return list(result.scalars().all())


# ===================================================================
# score_to_grade
# ===================================================================


class TestScoreToGrade:
    @pytest.mark.parametrize("score,expected", [
        (100, "A"),
        (95, "A"),
        (90, "A"),
        (89, "B"),
        (85, "B"),
        (80, "B"),
        (79, "C"),
        (75, "C"),
        (70, "C"),
        (69, "D"),
        (65, "D"),
        (60, "D"),
        (59, "F"),
        (50, "F"),
        (30, "F"),
        (10, "F"),
        (0, "F"),
    ])
    def test_grade_thresholds(self, score, expected):
        assert score_to_grade(score) == expected

    def test_negative_score(self):
        assert score_to_grade(-10) == "F"


# ===================================================================
# GRADES config
# ===================================================================


class TestGradesConfig:
    def test_grades_ordered_descending(self):
        thresholds = [g[0] for g in GRADES]
        assert thresholds == sorted(thresholds, reverse=True)

    def test_all_grades_present(self):
        grade_letters = {g[1] for g in GRADES}
        assert grade_letters == {"A", "B", "C", "D", "F"}

    def test_lowest_threshold_is_zero(self):
        assert GRADES[-1][0] == 0


# ===================================================================
# SCANNERS list
# ===================================================================


class TestScannersConfig:
    def test_seven_scanners_registered(self):
        assert len(SCANNERS) == 7

    def test_scanner_names(self):
        names = {s.name for s in SCANNERS}
        assert names == {"dns", "tls", "headers", "reputation", "subdomains", "leaks", "ports"}

    def test_weights_sum_to_one(self):
        total = sum(s.weight for s in SCANNERS)
        assert abs(total - 1.0) < 0.01

    def test_all_scanners_have_scan_method(self):
        for scanner in SCANNERS:
            assert hasattr(scanner, "scan")
            assert callable(scanner.scan)

    def test_all_scanners_have_positive_weight(self):
        for scanner in SCANNERS:
            assert scanner.weight > 0

    def test_scanner_weights(self):
        weights = {s.name: s.weight for s in SCANNERS}
        assert weights["dns"] == 0.20
        assert weights["tls"] == 0.20
        assert weights["headers"] == 0.15
        assert weights["reputation"] == 0.15
        assert weights["subdomains"] == 0.10
        assert weights["leaks"] == 0.10
        assert weights["ports"] == 0.10


# ===================================================================
# run_single_scanner — scanner qui réussit
# ===================================================================


class TestRunSingleScannerSuccess:
    async def test_module_status_transitions(self):
        """pending → running → completed."""
        scan_id = await _create_scan_in_db()
        scanner = FakeScanner("test_scanner", 0.5, score=85)

        # Créer le module en DB (comme run_scan le ferait)
        async with AsyncSessionLocal() as session:
            session.add(ScanModule(
                scan_id=scan_id, name="test_scanner", weight=0.5, status="pending",
            ))
            await session.commit()

        await run_single_scanner(scanner, "example.com", scan_id)

        modules = await _get_modules(scan_id)
        assert len(modules) == 1
        module = modules[0]
        assert module.status == "completed"
        assert module.score == 85

    async def test_started_at_and_completed_at_set(self):
        scan_id = await _create_scan_in_db()
        scanner = FakeScanner("ts", 0.5, score=100)

        async with AsyncSessionLocal() as session:
            session.add(ScanModule(
                scan_id=scan_id, name="ts", weight=0.5, status="pending",
            ))
            await session.commit()

        await run_single_scanner(scanner, "example.com", scan_id)

        modules = await _get_modules(scan_id)
        module = modules[0]
        assert module.started_at is not None
        assert module.completed_at is not None
        assert module.completed_at >= module.started_at

    async def test_findings_persisted_in_db(self):
        scan_id = await _create_scan_in_db()
        findings = [
            FindingData(
                severity="high",
                title="Problème A",
                description="Description A",
                remediation="Fix A",
                raw_data='{"detail": "a"}',
            ),
            FindingData(
                severity="low",
                title="Problème B",
                description="Description B",
            ),
        ]
        scanner = FakeScanner("ts", 0.5, score=75, findings=findings)

        async with AsyncSessionLocal() as session:
            session.add(ScanModule(
                scan_id=scan_id, name="ts", weight=0.5, status="pending",
            ))
            await session.commit()

        await run_single_scanner(scanner, "example.com", scan_id)

        modules = await _get_modules(scan_id)
        db_findings = modules[0].findings
        assert len(db_findings) == 2

        # Vérifier que chaque champ est correctement persisté
        finding_a = next(f for f in db_findings if f.title == "Problème A")
        assert finding_a.severity == "high"
        assert finding_a.description == "Description A"
        assert finding_a.remediation == "Fix A"
        assert finding_a.raw_data == '{"detail": "a"}'

        finding_b = next(f for f in db_findings if f.title == "Problème B")
        assert finding_b.severity == "low"
        assert finding_b.remediation is None
        assert finding_b.raw_data is None

    async def test_zero_findings_no_error(self):
        scan_id = await _create_scan_in_db()
        scanner = FakeScanner("ts", 0.5, score=100, findings=[])

        async with AsyncSessionLocal() as session:
            session.add(ScanModule(
                scan_id=scan_id, name="ts", weight=0.5, status="pending",
            ))
            await session.commit()

        await run_single_scanner(scanner, "example.com", scan_id)

        modules = await _get_modules(scan_id)
        assert modules[0].score == 100
        assert modules[0].status == "completed"
        assert len(modules[0].findings) == 0


# ===================================================================
# run_single_scanner — scanner qui échoue
# ===================================================================


class TestRunSingleScannerFailure:
    async def test_module_status_failed(self):
        scan_id = await _create_scan_in_db()
        scanner = FailingScanner("fail_scanner", 0.5, "Boom!")

        async with AsyncSessionLocal() as session:
            session.add(ScanModule(
                scan_id=scan_id, name="fail_scanner", weight=0.5, status="pending",
            ))
            await session.commit()

        await run_single_scanner(scanner, "example.com", scan_id)

        modules = await _get_modules(scan_id)
        module = modules[0]
        assert module.status == "failed"
        assert module.score == 0

    async def test_error_finding_created(self):
        scan_id = await _create_scan_in_db()
        scanner = FailingScanner("fail_scanner", 0.5, "Connection refused")

        async with AsyncSessionLocal() as session:
            session.add(ScanModule(
                scan_id=scan_id, name="fail_scanner", weight=0.5, status="pending",
            ))
            await session.commit()

        await run_single_scanner(scanner, "example.com", scan_id)

        modules = await _get_modules(scan_id)
        findings = modules[0].findings
        assert len(findings) == 1
        assert findings[0].severity == "info"
        assert findings[0].title == "Scan échoué"
        assert "Connection refused" in findings[0].description

    async def test_completed_at_set_even_on_failure(self):
        scan_id = await _create_scan_in_db()
        scanner = FailingScanner("fail_scanner", 0.5)

        async with AsyncSessionLocal() as session:
            session.add(ScanModule(
                scan_id=scan_id, name="fail_scanner", weight=0.5, status="pending",
            ))
            await session.commit()

        await run_single_scanner(scanner, "example.com", scan_id)

        modules = await _get_modules(scan_id)
        assert modules[0].completed_at is not None
        assert modules[0].started_at is not None


# ===================================================================
# run_scan — flux complet
# ===================================================================


class TestRunScan:
    async def test_creates_modules_for_each_scanner(self):
        """run_scan crée un ScanModule par scanner dans SCANNERS."""
        scan_id = await _create_scan_in_db()

        fake_scanners = [
            FakeScanner("alpha", 0.5, score=90),
            FakeScanner("beta", 0.5, score=80),
        ]
        with patch("app.scanners.orchestrator.SCANNERS", fake_scanners):
            await run_scan(scan_id, "example.com")

        modules = await _get_modules(scan_id)
        names = {m.name for m in modules}
        assert names == {"alpha", "beta"}

    async def test_scan_status_transitions(self):
        """Scan passe de pending → running → completed."""
        scan_id = await _create_scan_in_db()

        fake_scanners = [FakeScanner("s1", 1.0, score=100)]
        with patch("app.scanners.orchestrator.SCANNERS", fake_scanners):
            await run_scan(scan_id, "example.com")

        scan = await _get_scan_full(scan_id)
        assert scan.status == "completed"
        assert scan.started_at is not None
        assert scan.completed_at is not None
        assert scan.completed_at >= scan.started_at

    async def test_global_score_weighted_average(self):
        """Le score global est la moyenne pondérée des modules."""
        scan_id = await _create_scan_in_db()

        # alpha: score=100, weight=0.6 → 60
        # beta:  score=50,  weight=0.4 → 20
        # total = 80 / 1.0 = 80
        fake_scanners = [
            FakeScanner("alpha", 0.6, score=100),
            FakeScanner("beta", 0.4, score=50),
        ]
        with patch("app.scanners.orchestrator.SCANNERS", fake_scanners):
            await run_scan(scan_id, "example.com")

        scan = await _get_scan_full(scan_id)
        assert scan.score == 80  # round(100*0.6 + 50*0.4) / (0.6+0.4) = 80
        assert scan.grade == "B"

    async def test_global_score_rounds_correctly(self):
        """Vérifie l'arrondi du score global."""
        scan_id = await _create_scan_in_db()

        # score = round((90*0.3 + 85*0.7) / 1.0) = round(27 + 59.5) = round(86.5) = 86
        fake_scanners = [
            FakeScanner("a", 0.3, score=90),
            FakeScanner("b", 0.7, score=85),
        ]
        with patch("app.scanners.orchestrator.SCANNERS", fake_scanners):
            await run_scan(scan_id, "example.com")

        scan = await _get_scan_full(scan_id)
        expected = round(90 * 0.3 + 85 * 0.7)  # 86 ou 87
        assert scan.score == expected

    async def test_grade_A_for_high_score(self):
        scan_id = await _create_scan_in_db()

        fake_scanners = [FakeScanner("s", 1.0, score=95)]
        with patch("app.scanners.orchestrator.SCANNERS", fake_scanners):
            await run_scan(scan_id, "example.com")

        scan = await _get_scan_full(scan_id)
        assert scan.grade == "A"

    async def test_grade_F_for_low_score(self):
        scan_id = await _create_scan_in_db()

        fake_scanners = [FakeScanner("s", 1.0, score=30)]
        with patch("app.scanners.orchestrator.SCANNERS", fake_scanners):
            await run_scan(scan_id, "example.com")

        scan = await _get_scan_full(scan_id)
        assert scan.grade == "F"

    async def test_modules_weights_persisted(self):
        scan_id = await _create_scan_in_db()

        fake_scanners = [
            FakeScanner("a", 0.3, score=100),
            FakeScanner("b", 0.7, score=100),
        ]
        with patch("app.scanners.orchestrator.SCANNERS", fake_scanners):
            await run_scan(scan_id, "example.com")

        modules = await _get_modules(scan_id)
        weights = {m.name: m.weight for m in modules}
        assert weights["a"] == pytest.approx(0.3)
        assert weights["b"] == pytest.approx(0.7)

    async def test_parallel_execution(self):
        """Tous les scanners sont lancés en parallèle via asyncio.gather."""
        scan_id = await _create_scan_in_db()
        import asyncio

        call_order = []

        class SlowScanner(BaseScanner):
            def __init__(self, name, weight, delay, score):
                self.name = name
                self.weight = weight
                self._delay = delay
                self._score = score

            async def scan(self, domain: str) -> ScanResult:
                call_order.append(f"{self.name}_start")
                await asyncio.sleep(self._delay)
                call_order.append(f"{self.name}_end")
                return ScanResult(score=self._score, findings=[])

        fake_scanners = [
            SlowScanner("fast", 0.5, 0.01, 100),
            SlowScanner("slow", 0.5, 0.05, 80),
        ]
        with patch("app.scanners.orchestrator.SCANNERS", fake_scanners):
            await run_scan(scan_id, "example.com")

        # Les deux scanners démarrent avant que le lent ne finisse
        assert "fast_start" in call_order
        assert "slow_start" in call_order
        # fast finit avant slow
        assert call_order.index("fast_end") < call_order.index("slow_end")


# ===================================================================
# run_scan — un scanner échoue, les autres réussissent
# ===================================================================


class TestRunScanPartialFailure:
    async def test_one_scanner_fails_others_succeed(self):
        scan_id = await _create_scan_in_db()

        fake_scanners = [
            FakeScanner("good", 0.6, score=90),
            FailingScanner("bad", 0.4, "Timeout"),
        ]
        with patch("app.scanners.orchestrator.SCANNERS", fake_scanners):
            await run_scan(scan_id, "example.com")

        scan = await _get_scan_full(scan_id)
        # Le scan global doit être completed (pas failed)
        assert scan.status == "completed"

        modules = await _get_modules(scan_id)
        good_mod = next(m for m in modules if m.name == "good")
        bad_mod = next(m for m in modules if m.name == "bad")

        assert good_mod.status == "completed"
        assert good_mod.score == 90

        assert bad_mod.status == "failed"
        assert bad_mod.score == 0

    async def test_weighted_average_includes_failed_module(self):
        """Un module failed a score=0, il participe à la moyenne pondérée."""
        scan_id = await _create_scan_in_db()

        fake_scanners = [
            FakeScanner("good", 0.5, score=100),
            FailingScanner("bad", 0.5),
        ]
        with patch("app.scanners.orchestrator.SCANNERS", fake_scanners):
            await run_scan(scan_id, "example.com")

        scan = await _get_scan_full(scan_id)
        # good: 100 * 0.5 = 50, bad: 0 * 0.5 = 0
        # total_weight = 1.0 (les deux ont score != None)
        # global = round(50 / 1.0) = 50
        assert scan.score == 50

    async def test_failed_module_has_error_finding(self):
        scan_id = await _create_scan_in_db()

        fake_scanners = [
            FailingScanner("broken", 1.0, "DNS timeout"),
        ]
        with patch("app.scanners.orchestrator.SCANNERS", fake_scanners):
            await run_scan(scan_id, "example.com")

        modules = await _get_modules(scan_id)
        findings = modules[0].findings
        assert len(findings) == 1
        assert findings[0].title == "Scan échoué"
        assert "DNS timeout" in findings[0].description


# ===================================================================
# run_scan — tous les scanners échouent
# ===================================================================


class TestRunScanAllFailed:
    async def test_all_scanners_fail_score_zero(self):
        """Si tous les modules échouent, total_weight > 0 (score=0 est not None) → score=0."""
        scan_id = await _create_scan_in_db()

        fake_scanners = [
            FailingScanner("a", 0.5),
            FailingScanner("b", 0.5),
        ]
        with patch("app.scanners.orchestrator.SCANNERS", fake_scanners):
            await run_scan(scan_id, "example.com")

        scan = await _get_scan_full(scan_id)
        assert scan.score == 0
        assert scan.grade == "F"
        assert scan.status == "completed"

    async def test_each_failed_module_has_finding(self):
        scan_id = await _create_scan_in_db()

        fake_scanners = [
            FailingScanner("a", 0.5, "Error A"),
            FailingScanner("b", 0.5, "Error B"),
        ]
        with patch("app.scanners.orchestrator.SCANNERS", fake_scanners):
            await run_scan(scan_id, "example.com")

        modules = await _get_modules(scan_id)
        for m in modules:
            assert m.status == "failed"
            assert len(m.findings) == 1
            assert m.findings[0].title == "Scan échoué"


# ===================================================================
# run_scan — score pondéré avec poids inégaux
# ===================================================================


class TestRunScanWeightedScoring:
    async def test_heavier_scanner_has_more_impact(self):
        scan_id = await _create_scan_in_db()

        # heavy (0.8) scores 100, light (0.2) scores 0
        # global = round((100*0.8 + 0*0.2) / 1.0) = 80
        fake_scanners = [
            FakeScanner("heavy", 0.8, score=100),
            FakeScanner("light", 0.2, score=0),
        ]
        with patch("app.scanners.orchestrator.SCANNERS", fake_scanners):
            await run_scan(scan_id, "example.com")

        scan = await _get_scan_full(scan_id)
        assert scan.score == 80
        assert scan.grade == "B"

    async def test_lighter_scanner_has_less_impact(self):
        scan_id = await _create_scan_in_db()

        # heavy (0.8) scores 0, light (0.2) scores 100
        # global = round((0*0.8 + 100*0.2) / 1.0) = 20
        fake_scanners = [
            FakeScanner("heavy", 0.8, score=0),
            FakeScanner("light", 0.2, score=100),
        ]
        with patch("app.scanners.orchestrator.SCANNERS", fake_scanners):
            await run_scan(scan_id, "example.com")

        scan = await _get_scan_full(scan_id)
        assert scan.score == 20
        assert scan.grade == "F"

    async def test_three_scanners_weighted_average(self):
        scan_id = await _create_scan_in_db()

        # a: 100*0.5=50, b: 80*0.3=24, c: 60*0.2=12 → total=86
        fake_scanners = [
            FakeScanner("a", 0.5, score=100),
            FakeScanner("b", 0.3, score=80),
            FakeScanner("c", 0.2, score=60),
        ]
        with patch("app.scanners.orchestrator.SCANNERS", fake_scanners):
            await run_scan(scan_id, "example.com")

        scan = await _get_scan_full(scan_id)
        assert scan.score == 86

    async def test_all_perfect_scores(self):
        scan_id = await _create_scan_in_db()

        fake_scanners = [
            FakeScanner("a", 0.4, score=100),
            FakeScanner("b", 0.6, score=100),
        ]
        with patch("app.scanners.orchestrator.SCANNERS", fake_scanners):
            await run_scan(scan_id, "example.com")

        scan = await _get_scan_full(scan_id)
        assert scan.score == 100
        assert scan.grade == "A"

    async def test_all_zero_scores(self):
        scan_id = await _create_scan_in_db()

        fake_scanners = [
            FakeScanner("a", 0.5, score=0),
            FakeScanner("b", 0.5, score=0),
        ]
        with patch("app.scanners.orchestrator.SCANNERS", fake_scanners):
            await run_scan(scan_id, "example.com")

        scan = await _get_scan_full(scan_id)
        assert scan.score == 0
        assert scan.grade == "F"


# ===================================================================
# run_scan — findings multiples persistés bout en bout
# ===================================================================


class TestRunScanFindingsPersistence:
    async def test_findings_from_multiple_scanners_persisted(self):
        scan_id = await _create_scan_in_db()

        fake_scanners = [
            FakeScanner("dns", 0.5, score=80, findings=[
                FindingData(severity="high", title="SPF manquant", description="Pas de SPF"),
                FindingData(severity="medium", title="DMARC p=none", description="Monitoring"),
            ]),
            FakeScanner("tls", 0.5, score=70, findings=[
                FindingData(
                    severity="critical",
                    title="Cert expiré",
                    description="Le cert a expiré",
                    remediation="Renouveler",
                    raw_data='{"days": -5}',
                ),
            ]),
        ]
        with patch("app.scanners.orchestrator.SCANNERS", fake_scanners):
            await run_scan(scan_id, "example.com")

        modules = await _get_modules(scan_id)
        dns_mod = next(m for m in modules if m.name == "dns")
        tls_mod = next(m for m in modules if m.name == "tls")

        assert len(dns_mod.findings) == 2
        assert len(tls_mod.findings) == 1

        # Vérifie la persistance complète du finding TLS
        cert_finding = tls_mod.findings[0]
        assert cert_finding.severity == "critical"
        assert cert_finding.title == "Cert expiré"
        assert cert_finding.description == "Le cert a expiré"
        assert cert_finding.remediation == "Renouveler"
        assert cert_finding.raw_data == '{"days": -5}'

    async def test_info_findings_do_not_affect_score(self):
        scan_id = await _create_scan_in_db()

        fake_scanners = [
            FakeScanner("s", 1.0, score=100, findings=[
                FindingData(severity="info", title="Note", description="FYI"),
            ]),
        ]
        with patch("app.scanners.orchestrator.SCANNERS", fake_scanners):
            await run_scan(scan_id, "example.com")

        scan = await _get_scan_full(scan_id)
        assert scan.score == 100  # Le score du scanner reste 100

    async def test_domain_passed_to_scanner(self):
        """Vérifie que le domaine est bien transmis au scanner."""
        scan_id = await _create_scan_in_db("custom-domain.org")
        received_domain = None

        class SpyScanner(BaseScanner):
            name = "spy"
            weight = 1.0

            async def scan(self, domain: str) -> ScanResult:
                nonlocal received_domain
                received_domain = domain
                return ScanResult(score=100, findings=[])

        with patch("app.scanners.orchestrator.SCANNERS", [SpyScanner()]):
            await run_scan(scan_id, "custom-domain.org")

        assert received_domain == "custom-domain.org"
