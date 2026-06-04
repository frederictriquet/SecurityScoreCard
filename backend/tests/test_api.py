"""Tests pour les routes API — endpoints CRUD scans, intégration, rate limiting."""

import asyncio
import pytest
from unittest.mock import patch, AsyncMock

from httpx import AsyncClient, ASGITransport
from sqlalchemy import select, func
from sqlalchemy.orm import selectinload

from app.database import Base, engine, AsyncSessionLocal
from app.models import Scan, ScanModule, Finding
from app.main import app
from app.limiter import limiter
from app.scanners.base import BaseScanner, ScanResult, FindingData


# ===================================================================
# Fixtures
# ===================================================================


@pytest.fixture(autouse=True)
async def setup_db():
    """Crée les tables avant chaque test et les supprime après."""
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)


@pytest.fixture
async def client():
    """Client HTTP avec rate limiting désactivé (par défaut)."""
    limiter.enabled = False
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as c:
        yield c
    limiter.enabled = True


@pytest.fixture
async def client_with_rate_limit():
    """Client HTTP avec rate limiting ACTIVÉ."""
    limiter.enabled = True
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as c:
        yield c
    limiter.enabled = True


async def _create_scan(client, domain="example.com"):
    """Helper pour créer un scan (run_scan mocké) et retourner la réponse."""
    with patch("app.routers.scans.run_scan", new_callable=AsyncMock):
        resp = await client.post("/api/scans", json={"domain": domain})
    return resp


async def _create_scan_with_orchestrator(client, domain="example.com", scanners=None):
    """Crée un scan ET exécute l'orchestrateur avec des scanners factices."""
    if scanners is None:
        scanners = [_FakeScanner("fake", 1.0, 100, [])]
    with patch("app.scanners.orchestrator.SCANNERS", scanners):
        resp = await client.post("/api/scans", json={"domain": domain})
    return resp


class _FakeScanner(BaseScanner):
    def __init__(self, name, weight, score, findings=None):
        self.name = name
        self.weight = weight
        self._score = score
        self._findings = findings or []

    async def scan(self, domain: str) -> ScanResult:
        return ScanResult(score=self._score, findings=self._findings)


class _FailingScanner(BaseScanner):
    def __init__(self, name, weight, msg="crash"):
        self.name = name
        self.weight = weight
        self._msg = msg

    async def scan(self, domain: str) -> ScanResult:
        raise RuntimeError(self._msg)


async def _count_rows(model) -> int:
    async with AsyncSessionLocal() as session:
        result = await session.execute(select(func.count()).select_from(model))
        return result.scalar()


async def _get_scan_with_modules(scan_id: str) -> Scan:
    async with AsyncSessionLocal() as session:
        result = await session.execute(
            select(Scan)
            .options(selectinload(Scan.modules).selectinload(ScanModule.findings))
            .where(Scan.id == scan_id)
        )
        return result.scalar_one()


# ===================================================================
# Health endpoint
# ===================================================================


class TestHealth:
    async def test_health_returns_ok(self, client):
        resp = await client.get("/health")
        assert resp.status_code == 200
        assert resp.json() == {"status": "ok"}


# ===================================================================
# POST /api/scans — unit tests (run_scan mocké)
# ===================================================================


class TestCreateScan:
    async def test_create_scan_valid_domain(self, client):
        resp = await _create_scan(client)
        assert resp.status_code == 201
        data = resp.json()
        assert data["domain"] == "example.com"
        assert data["status"] == "pending"
        assert data["id"] is not None
        assert data["score"] is None
        assert data["grade"] is None
        assert data["modules"] == []

    async def test_create_scan_strips_https(self, client):
        resp = await _create_scan(client, "https://Example.COM/")
        assert resp.status_code == 201
        assert resp.json()["domain"] == "example.com"

    async def test_create_scan_invalid_domain(self, client):
        resp = await client.post("/api/scans", json={"domain": "not valid"})
        assert resp.status_code == 422

    async def test_create_scan_empty_domain(self, client):
        resp = await client.post("/api/scans", json={"domain": ""})
        assert resp.status_code == 422

    async def test_create_scan_missing_domain(self, client):
        resp = await client.post("/api/scans", json={})
        assert resp.status_code == 422

    async def test_create_scan_triggers_background_task(self, client):
        with patch("app.routers.scans.run_scan", new_callable=AsyncMock) as mock_run:
            resp = await client.post("/api/scans", json={"domain": "example.com"})
            assert resp.status_code == 201
            scan_id = resp.json()["id"]
            mock_run.assert_called_once_with(scan_id, "example.com")


# ===================================================================
# POST /api/scans — confirmation préalable d'un domaine homographe
# ===================================================================


class TestCreateScanHomographConfirmation:
    """Un domaine homographe valide exige une confirmation explicite.

    « pаypal.com » (« а » cyrillique) se convertit en Punycode valide et passerait
    silencieusement la validation : on refuse de le scanner sans avertir, en
    renvoyant une réponse « confirmation requise » qui explique le danger. Le scan
    ne démarre qu'avec `confirm: true`. Les domaines non homographes (y compris les
    IDN légitimes) continuent de scanner directement.
    """

    HOMOGRAPH = "pаypal.com"  # « а » cyrillique (U+0430)
    HOMOGRAPH_PUNYCODE = "xn--pypal-4ve.com"

    async def test_homograph_without_confirm_requires_confirmation(self, client):
        with patch("app.routers.scans.run_scan", new_callable=AsyncMock) as mock_run:
            resp = await client.post("/api/scans", json={"domain": self.HOMOGRAPH})
        assert resp.status_code == 409
        detail = resp.json()["detail"]
        assert detail["needs_confirmation"] is True
        assert "homographe" in detail["explanation"].lower()
        assert detail["domain"] == self.HOMOGRAPH
        assert detail["punycode"] == self.HOMOGRAPH_PUNYCODE
        # Aucun scan créé, aucune tâche de fond lancée.
        mock_run.assert_not_called()
        assert await _count_rows(Scan) == 0

    async def test_homograph_with_confirm_creates_scan(self, client):
        with patch("app.routers.scans.run_scan", new_callable=AsyncMock) as mock_run:
            resp = await client.post(
                "/api/scans", json={"domain": self.HOMOGRAPH, "confirm": True}
            )
        assert resp.status_code == 201
        data = resp.json()
        assert data["domain"] == self.HOMOGRAPH_PUNYCODE
        scan_id = data["id"]
        mock_run.assert_called_once_with(scan_id, self.HOMOGRAPH_PUNYCODE)
        assert await _count_rows(Scan) == 1

    async def test_normal_domain_scans_without_confirmation(self, client):
        with patch("app.routers.scans.run_scan", new_callable=AsyncMock) as mock_run:
            resp = await client.post("/api/scans", json={"domain": "example.com"})
        assert resp.status_code == 201
        assert resp.json()["domain"] == "example.com"
        mock_run.assert_called_once()
        assert await _count_rows(Scan) == 1

    async def test_legit_idn_scans_without_confirmation(self, client):
        # IDN légitime (CJK, non confusable) : pas de signature homographe, le scan
        # démarre directement sans étape de confirmation.
        with patch("app.routers.scans.run_scan", new_callable=AsyncMock) as mock_run:
            resp = await client.post("/api/scans", json={"domain": "中国.com"})
        assert resp.status_code == 201
        assert resp.json()["domain"] == "xn--fiqs8s.com"
        mock_run.assert_called_once()
        assert await _count_rows(Scan) == 1


# ===================================================================
# POST /api/scans — intégration E2E (vrai orchestrateur)
# ===================================================================


class TestCreateScanE2E:
    async def test_full_flow_scan_to_completed(self, client):
        """API → orchestrateur → fake scanners → DB → réponse complète via GET."""
        scanners = [
            _FakeScanner("dns", 0.5, score=80, findings=[
                FindingData(severity="high", title="SPF manquant", description="Pas de SPF"),
            ]),
            _FakeScanner("tls", 0.5, score=100, findings=[]),
        ]
        resp = await _create_scan_with_orchestrator(client, "example.com", scanners)
        assert resp.status_code == 201
        scan_id = resp.json()["id"]

        # Relire via l'API GET pour obtenir l'état final avec modules et findings
        get_resp = await client.get(f"/api/scans/{scan_id}")
        data = get_resp.json()
        assert data["status"] == "completed"
        assert data["score"] == 90  # (80*0.5 + 100*0.5) / 1.0 = 90
        assert data["grade"] == "A"
        assert len(data["modules"]) == 2

        dns_mod = next(m for m in data["modules"] if m["name"] == "dns")
        tls_mod = next(m for m in data["modules"] if m["name"] == "tls")
        assert dns_mod["score"] == 80
        assert dns_mod["status"] == "completed"
        assert len(dns_mod["findings"]) == 1
        assert dns_mod["findings"][0]["title"] == "SPF manquant"
        assert tls_mod["score"] == 100
        assert len(tls_mod["findings"]) == 0

    async def test_e2e_get_scan_returns_modules_and_findings(self, client):
        """GET /api/scans/{id} retourne les modules et findings après exécution."""
        scanners = [
            _FakeScanner("headers", 1.0, score=70, findings=[
                FindingData(severity="medium", title="CSP manquant", description="Pas de CSP"),
                FindingData(severity="low", title="Referrer-Policy", description="Manquant"),
            ]),
        ]
        resp = await _create_scan_with_orchestrator(client, "test.org", scanners)
        scan_id = resp.json()["id"]

        get_resp = await client.get(f"/api/scans/{scan_id}")
        assert get_resp.status_code == 200
        data = get_resp.json()
        assert data["status"] == "completed"
        assert data["domain"] == "test.org"
        assert len(data["modules"]) == 1
        assert data["modules"][0]["name"] == "headers"
        assert data["modules"][0]["score"] == 70
        assert len(data["modules"][0]["findings"]) == 2

    async def test_e2e_scanner_failure_handled(self, client):
        """Un scanner qui crash ne fait pas échouer le scan global."""
        scanners = [
            _FakeScanner("good", 0.5, score=100),
            _FailingScanner("broken", 0.5, "Network error"),
        ]
        resp = await _create_scan_with_orchestrator(client, "example.com", scanners)
        scan_id = resp.json()["id"]

        scan = await _get_scan_with_modules(scan_id)
        assert scan.status == "completed"
        assert scan.score == 50  # (100*0.5 + 0*0.5) / 1.0

        broken_mod = next(m for m in scan.modules if m.name == "broken")
        assert broken_mod.status == "failed"
        assert broken_mod.score == 0
        assert len(broken_mod.findings) == 1
        assert "Network error" in broken_mod.findings[0].description

    async def test_e2e_all_scanners_fail(self, client):
        scanners = [
            _FailingScanner("a", 0.5, "Boom"),
            _FailingScanner("b", 0.5, "Bang"),
        ]
        resp = await _create_scan_with_orchestrator(client, "fail.com", scanners)
        scan_id = resp.json()["id"]

        scan = await _get_scan_with_modules(scan_id)
        assert scan.status == "completed"
        assert scan.score == 0
        assert scan.grade == "F"

    async def test_e2e_findings_persisted_with_all_fields(self, client):
        """Vérifie que remediation et raw_data traversent toute la chaîne."""
        scanners = [
            _FakeScanner("tls", 1.0, score=70, findings=[
                FindingData(
                    severity="critical",
                    title="Cert expiré",
                    description="Expiré depuis 5 jours",
                    remediation="Renouveler avec Let's Encrypt",
                    raw_data='{"expired_days": 5}',
                ),
            ]),
        ]
        resp = await _create_scan_with_orchestrator(client, "expired.com", scanners)
        scan_id = resp.json()["id"]

        get_resp = await client.get(f"/api/scans/{scan_id}")
        finding = get_resp.json()["modules"][0]["findings"][0]
        assert finding["severity"] == "critical"
        assert finding["title"] == "Cert expiré"
        assert finding["description"] == "Expiré depuis 5 jours"
        assert finding["remediation"] == "Renouveler avec Let's Encrypt"


# ===================================================================
# GET /api/scans
# ===================================================================


class TestListScans:
    async def test_list_scans_empty(self, client):
        resp = await client.get("/api/scans")
        assert resp.status_code == 200
        assert resp.json() == []

    async def test_list_scans_after_create(self, client):
        await _create_scan(client, "example.com")
        await _create_scan(client, "test.org")

        resp = await client.get("/api/scans")
        assert resp.status_code == 200
        data = resp.json()
        assert len(data) == 2

    async def test_list_scans_returns_summary_fields(self, client):
        await _create_scan(client)

        resp = await client.get("/api/scans")
        data = resp.json()
        assert len(data) >= 1
        scan = data[0]
        assert "id" in scan
        assert "domain" in scan
        assert "status" in scan
        assert "score" in scan
        assert "grade" in scan
        assert "created_at" in scan
        # ScanSummary ne contient pas modules
        assert "modules" not in scan

    async def test_list_scans_limited_to_50(self, client):
        """L'API retourne max 50 scans même s'il y en a plus."""
        for i in range(55):
            await _create_scan(client, f"domain{i}.com")

        resp = await client.get("/api/scans")
        data = resp.json()
        assert len(data) == 50


# ===================================================================
# GET /api/scans/{scan_id}
# ===================================================================


class TestGetScan:
    async def test_get_scan_exists(self, client):
        create_resp = await _create_scan(client)
        scan_id = create_resp.json()["id"]

        resp = await client.get(f"/api/scans/{scan_id}")
        assert resp.status_code == 200
        data = resp.json()
        assert data["id"] == scan_id
        assert data["domain"] == "example.com"
        assert "modules" in data

    async def test_get_scan_not_found(self, client):
        resp = await client.get("/api/scans/nonexistent-id")
        assert resp.status_code == 404
        assert "introuvable" in resp.json()["detail"].lower()

    async def test_get_scan_with_completed_modules(self, client):
        """GET retourne les modules et findings après exécution E2E."""
        scanners = [_FakeScanner("s", 1.0, 95, [
            FindingData(severity="low", title="Minor", description="D"),
        ])]
        resp = await _create_scan_with_orchestrator(client, "example.com", scanners)
        scan_id = resp.json()["id"]

        get_resp = await client.get(f"/api/scans/{scan_id}")
        data = get_resp.json()
        assert data["score"] == 95
        assert data["grade"] == "A"
        assert len(data["modules"]) == 1
        assert data["modules"][0]["status"] == "completed"
        assert len(data["modules"][0]["findings"]) == 1


# ===================================================================
# DELETE /api/scans/{scan_id}
# ===================================================================


class TestDeleteScan:
    async def test_delete_scan_exists(self, client):
        create_resp = await _create_scan(client)
        scan_id = create_resp.json()["id"]

        resp = await client.delete(f"/api/scans/{scan_id}")
        assert resp.status_code == 204

        resp = await client.get(f"/api/scans/{scan_id}")
        assert resp.status_code == 404

    async def test_delete_scan_not_found(self, client):
        resp = await client.delete("/api/scans/nonexistent-id")
        assert resp.status_code == 404

    async def test_delete_cascades_modules_and_findings(self, client):
        """DELETE supprime aussi les ScanModule et Finding associés."""
        scanners = [_FakeScanner("s", 1.0, 80, [
            FindingData(severity="high", title="Issue", description="Desc"),
        ])]
        resp = await _create_scan_with_orchestrator(client, "example.com", scanners)
        scan_id = resp.json()["id"]

        # Vérifier qu'il y a des modules et findings en DB
        assert await _count_rows(ScanModule) >= 1
        assert await _count_rows(Finding) >= 1

        await client.delete(f"/api/scans/{scan_id}")

        # Tout est supprimé en cascade
        assert await _count_rows(Scan) == 0
        assert await _count_rows(ScanModule) == 0
        assert await _count_rows(Finding) == 0

    async def test_delete_one_scan_does_not_affect_others(self, client):
        resp1 = await _create_scan(client, "keep.com")
        resp2 = await _create_scan(client, "delete.com")
        id_keep = resp1.json()["id"]
        id_delete = resp2.json()["id"]

        await client.delete(f"/api/scans/{id_delete}")

        assert await _count_rows(Scan) == 1
        resp = await client.get(f"/api/scans/{id_keep}")
        assert resp.status_code == 200


# ===================================================================
# POST /api/scans/{scan_id}/rescan — unit tests
# ===================================================================


class TestRescan:
    async def test_rescan_resets_scan(self, client):
        create_resp = await _create_scan(client)
        scan_id = create_resp.json()["id"]

        with patch("app.routers.scans.run_scan", new_callable=AsyncMock):
            resp = await client.post(f"/api/scans/{scan_id}/rescan")
        assert resp.status_code == 200
        data = resp.json()
        assert data["id"] == scan_id
        assert data["status"] == "pending"
        assert data["score"] is None
        assert data["grade"] is None
        assert data["modules"] == []

    async def test_rescan_not_found(self, client):
        resp = await client.post("/api/scans/nonexistent-id/rescan")
        assert resp.status_code == 404

    async def test_rescan_preserves_domain(self, client):
        create_resp = await _create_scan(client, "test.org")
        scan_id = create_resp.json()["id"]

        with patch("app.routers.scans.run_scan", new_callable=AsyncMock):
            resp = await client.post(f"/api/scans/{scan_id}/rescan")
        assert resp.json()["domain"] == "test.org"


# ===================================================================
# POST /api/scans/{scan_id}/rescan — intégration cascade
# ===================================================================


class TestRescanCascade:
    async def test_rescan_deletes_old_modules_and_findings(self, client):
        """Le rescan supprime les anciens modules/findings puis en recrée."""
        scanners_v1 = [
            _FakeScanner("dns", 0.5, score=60, findings=[
                FindingData(severity="high", title="Old SPF", description="V1"),
                FindingData(severity="medium", title="Old DMARC", description="V1"),
            ]),
            _FakeScanner("tls", 0.5, score=50, findings=[
                FindingData(severity="critical", title="Old cert", description="V1"),
            ]),
        ]
        resp = await _create_scan_with_orchestrator(client, "example.com", scanners_v1)
        scan_id = resp.json()["id"]

        # V1 via GET API : 2 modules, 3 findings
        get_v1 = await client.get(f"/api/scans/{scan_id}")
        data_v1 = get_v1.json()
        assert len(data_v1["modules"]) == 2
        total_findings_v1 = sum(len(m["findings"]) for m in data_v1["modules"])
        assert total_findings_v1 == 3
        old_module_ids = {m["id"] for m in data_v1["modules"]}

        # Rescan avec des scanners différents
        scanners_v2 = [
            _FakeScanner("dns", 0.5, score=90, findings=[
                FindingData(severity="low", title="New DNS note", description="V2"),
            ]),
            _FakeScanner("tls", 0.5, score=100, findings=[]),
        ]
        with patch("app.scanners.orchestrator.SCANNERS", scanners_v2):
            resp = await client.post(f"/api/scans/{scan_id}/rescan")
        assert resp.status_code == 200

        # V2 via GET API : anciens modules supprimés, nouveaux créés
        get_v2 = await client.get(f"/api/scans/{scan_id}")
        data_v2 = get_v2.json()
        assert data_v2["status"] == "completed"
        assert len(data_v2["modules"]) == 2

        new_module_ids = {m["id"] for m in data_v2["modules"]}
        assert old_module_ids.isdisjoint(new_module_ids), "Les modules V1 doivent être supprimés"

        total_findings_v2 = sum(len(m["findings"]) for m in data_v2["modules"])
        assert total_findings_v2 == 1  # seul le finding "New DNS note" subsiste

        dns_mod = next(m for m in data_v2["modules"] if m["name"] == "dns")
        assert dns_mod["findings"][0]["title"] == "New DNS note"

    async def test_rescan_old_findings_not_in_db(self, client):
        """Vérifie que les anciens Finding sont réellement purgés de la DB."""
        scanners_v1 = [
            _FakeScanner("s", 1.0, score=50, findings=[
                FindingData(severity="critical", title="Old critical", description="V1"),
            ]),
        ]
        resp = await _create_scan_with_orchestrator(client, "example.com", scanners_v1)
        scan_id = resp.json()["id"]

        # Compter les findings avant rescan
        count_before = await _count_rows(Finding)
        assert count_before >= 1

        scanners_v2 = [_FakeScanner("s", 1.0, score=100, findings=[])]
        with patch("app.scanners.orchestrator.SCANNERS", scanners_v2):
            await client.post(f"/api/scans/{scan_id}/rescan")

        # Aucun finding ne doit rester pour ce scan
        async with AsyncSessionLocal() as session:
            result = await session.execute(
                select(Finding)
                .join(ScanModule)
                .where(ScanModule.scan_id == scan_id)
            )
            findings = result.scalars().all()
        assert len(findings) == 0

    async def test_rescan_score_updates(self, client):
        """Le rescan recalcule le score avec les nouveaux résultats."""
        scanners_v1 = [_FakeScanner("s", 1.0, score=30)]
        resp = await _create_scan_with_orchestrator(client, "example.com", scanners_v1)
        scan_id = resp.json()["id"]

        scan_v1 = await _get_scan_with_modules(scan_id)
        assert scan_v1.score == 30
        assert scan_v1.grade == "F"

        scanners_v2 = [_FakeScanner("s", 1.0, score=95)]
        with patch("app.scanners.orchestrator.SCANNERS", scanners_v2):
            await client.post(f"/api/scans/{scan_id}/rescan")

        scan_v2 = await _get_scan_with_modules(scan_id)
        assert scan_v2.score == 95
        assert scan_v2.grade == "A"

    async def test_rescan_same_scan_id_preserved(self, client):
        """Le rescan ne crée pas un nouveau Scan, il réutilise le même ID."""
        resp = await _create_scan(client)
        scan_id = resp.json()["id"]

        with patch("app.routers.scans.run_scan", new_callable=AsyncMock):
            resp = await client.post(f"/api/scans/{scan_id}/rescan")
        assert resp.json()["id"] == scan_id
        assert await _count_rows(Scan) == 1

    async def test_rescan_timestamps_reset_and_updated(self, client):
        """started_at et completed_at sont réinitialisés puis repositionnés."""
        scanners = [_FakeScanner("s", 1.0, score=80)]
        resp = await _create_scan_with_orchestrator(client, "example.com", scanners)
        scan_id = resp.json()["id"]

        scan_v1 = await _get_scan_with_modules(scan_id)
        v1_created = scan_v1.created_at

        scanners_v2 = [_FakeScanner("s", 1.0, score=90)]
        with patch("app.scanners.orchestrator.SCANNERS", scanners_v2):
            await client.post(f"/api/scans/{scan_id}/rescan")

        scan_v2 = await _get_scan_with_modules(scan_id)
        assert scan_v2.created_at >= v1_created  # created_at a été rafraîchi par now_utc()
        assert scan_v2.started_at is not None
        assert scan_v2.completed_at is not None


# ===================================================================
# Rate limiting
# ===================================================================


class TestRateLimiting:
    async def test_create_scan_rate_limited_after_5(self, client_with_rate_limit):
        """POST /api/scans est limité à 5/minute."""
        c = client_with_rate_limit
        for i in range(5):
            with patch("app.routers.scans.run_scan", new_callable=AsyncMock):
                resp = await c.post("/api/scans", json={"domain": f"d{i}.com"})
            assert resp.status_code == 201, f"Request {i+1} should succeed"

        # La 6e requête doit être rejetée
        with patch("app.routers.scans.run_scan", new_callable=AsyncMock):
            resp = await c.post("/api/scans", json={"domain": "one-too-many.com"})
        assert resp.status_code == 429

    async def test_rescan_rate_limited_after_5(self, client_with_rate_limit):
        """POST /api/scans/{id}/rescan est limité à 5/minute."""
        c = client_with_rate_limit

        # Créer un scan (consomme 1 des 5 créations)
        # Note: le rate limit est par endpoint ET global default (30/min)
        # Créons le scan sans rate limit d'abord
        limiter.enabled = False
        resp = await _create_scan(c)
        scan_id = resp.json()["id"]
        limiter.enabled = True

        for i in range(5):
            with patch("app.routers.scans.run_scan", new_callable=AsyncMock):
                resp = await c.post(f"/api/scans/{scan_id}/rescan")
            assert resp.status_code == 200, f"Rescan {i+1} should succeed"

        with patch("app.routers.scans.run_scan", new_callable=AsyncMock):
            resp = await c.post(f"/api/scans/{scan_id}/rescan")
        assert resp.status_code == 429

    async def test_get_and_list_not_rate_limited_at_5(self, client_with_rate_limit):
        """GET endpoints ne sont pas limités à 5/min (default 30/min)."""
        c = client_with_rate_limit
        for _ in range(10):
            resp = await c.get("/api/scans")
            assert resp.status_code == 200


# ===================================================================
# Concurrence
# ===================================================================


class TestConcurrency:
    async def test_concurrent_rescans_race_condition(self, client):
        """Deux rescans simultanés révèlent une race condition connue.

        L'orchestrateur utilise scalar_one() pour retrouver le module par
        (scan_id, name), mais deux rescans concurrents créent des modules
        en double, ce qui peut causer MultipleResultsFound ou NoResultFound.

        Ce test documente le comportement : la concurrence provoque des erreurs
        DB au niveau de l'orchestrateur (background task), mais les endpoints
        HTTP retournent 200 car le rescan reset est fait AVANT le background task.
        """
        scanners = [_FakeScanner("s", 1.0, score=80)]
        resp = await _create_scan_with_orchestrator(client, "example.com", scanners)
        scan_id = resp.json()["id"]

        async def rescan_with(sc):
            with patch("app.scanners.orchestrator.SCANNERS", sc):
                return await client.post(f"/api/scans/{scan_id}/rescan")

        results = await asyncio.gather(
            rescan_with([_FakeScanner("s", 1.0, score=90)]),
            rescan_with([_FakeScanner("s", 1.0, score=70)]),
            return_exceptions=True,
        )

        # Les deux endpoints HTTP retournent 200 (le reset est synchrone),
        # mais les background tasks concurrentes peuvent échouer en DB.
        # On vérifie qu'il n'y a pas de crash non géré (pas d'exception Python propagée).
        for r in results:
            if isinstance(r, Exception):
                # Exceptions SQLAlchemy dans les background tasks sont acceptables
                # car elles sont capturées par Starlette et ne crashent pas le serveur
                assert "row" in str(r).lower() or "result" in str(r).lower(), \
                    f"Unexpected exception type: {r}"
            else:
                assert r.status_code == 200

        # Le scan existe toujours et est accessible
        get_resp = await client.get(f"/api/scans/{scan_id}")
        assert get_resp.status_code == 200

    async def test_concurrent_create_different_domains(self, client):
        """Créations simultanées sur des domaines différents ne s'interfèrent pas."""

        async def create(domain):
            with patch("app.routers.scans.run_scan", new_callable=AsyncMock):
                return await client.post("/api/scans", json={"domain": domain})

        results = await asyncio.gather(
            create("alpha.com"),
            create("beta.com"),
            create("gamma.com"),
        )

        assert all(r.status_code == 201 for r in results)
        domains = {r.json()["domain"] for r in results}
        assert domains == {"alpha.com", "beta.com", "gamma.com"}
        assert await _count_rows(Scan) == 3
