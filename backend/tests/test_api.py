"""Tests for the API routes — scans CRUD endpoints, integration, rate limiting."""

import asyncio
from typing import cast

import pytest
from unittest.mock import patch, AsyncMock

from httpx import AsyncClient, ASGITransport
from sqlalchemy import select, func
from sqlalchemy.orm import selectinload

import app.database as _db
from app.models import Scan, ScanModule, Finding
from app.main import app
from app.limiter import limiter
from app.scanners.base import BaseScanner, ScanResult, FindingData


# ===================================================================
# Fixtures
# ===================================================================


@pytest.fixture(autouse=True)
async def setup_db(isolated_db):
    """Each test gets a private SQLite file + fresh engine (see conftest)."""
    yield


@pytest.fixture
async def client():
    """HTTP client with rate limiting disabled (default)."""
    limiter.enabled = False
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as c:
        yield c
    limiter.enabled = True


@pytest.fixture
async def client_with_rate_limit():
    """HTTP client with rate limiting ENABLED."""
    limiter.enabled = True
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as c:
        yield c
    limiter.enabled = True


async def _create_scan(client, domain="example.com"):
    """Helper to create a scan (run_scan mocked) and return the response."""
    with patch("app.routers.scans.run_scan", new_callable=AsyncMock):
        resp = await client.post("/api/scans", json={"domain": domain})
    return resp


async def _create_scan_with_orchestrator(client, domain="example.com", scanners=None):
    """Create a scan AND run the orchestrator with fake scanners."""
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


class _SlowScanner(BaseScanner):
    """Scanner that suspends mid-scan, like real network I/O-bound scanners.

    A no-await scanner never lets two runners of the same module interleave, so
    it cannot expose the concurrent finding-duplication race. This one yields
    control so overlapping rescans genuinely overlap.
    """

    def __init__(self, name, weight, score, findings=None, delay=0.05):
        self.name = name
        self.weight = weight
        self._score = score
        self._findings = findings or []
        self._delay = delay

    async def scan(self, domain: str) -> ScanResult:
        await asyncio.sleep(self._delay)
        return ScanResult(score=self._score, findings=list(self._findings))


async def _count_rows(model) -> int:
    async with _db.AsyncSessionLocal() as session:
        result = await session.execute(select(func.count()).select_from(model))
        # ``count()`` always yields exactly one row, so the scalar is never None.
        return cast(int, result.scalar())


async def _get_scan_with_modules(scan_id: str) -> Scan:
    async with _db.AsyncSessionLocal() as session:
        result = await session.execute(
            select(Scan)
            .options(selectinload(Scan.modules).selectinload(ScanModule.findings))
            .where(Scan.id == scan_id)
        )
        return result.scalar_one()


async def _mark_completed(scan_id: str) -> None:
    """Force a scan into the ``completed`` state.

    The rescan endpoint only re-runs a scan that is in a terminal state. Unit
    tests that mock ``run_scan`` never let the background run finish, so the scan
    stays ``pending``; this helper puts it in the state a finished scan would
    really be in before a rescan.
    """
    async with _db.AsyncSessionLocal() as session:
        scan = (
            await session.execute(select(Scan).where(Scan.id == scan_id))
        ).scalar_one()
        scan.status = "completed"
        await session.commit()


# ===================================================================
# Health endpoint
# ===================================================================


class TestHealth:
    async def test_health_returns_ok(self, client):
        resp = await client.get("/health")
        assert resp.status_code == 200
        assert resp.json() == {"status": "ok"}


# ===================================================================
# POST /api/scans — unit tests (run_scan mocked)
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
# POST /api/scans — prior confirmation of a homograph domain
# ===================================================================


class TestCreateScanHomographConfirmation:
    """A valid homograph domain requires explicit confirmation.

    "pаypal.com" (Cyrillic "а") converts to valid Punycode and would silently pass
    validation: we refuse to scan it without warning, returning a "confirmation
    required" response that explains the danger. The scan only starts with
    `confirm: true`. Non-homograph domains (including legitimate IDNs) keep
    scanning directly.
    """

    HOMOGRAPH = "pаypal.com"  # Cyrillic "а" (U+0430)
    HOMOGRAPH_PUNYCODE = "xn--pypal-4ve.com"

    async def test_homograph_without_confirm_requires_confirmation(self, client):
        with patch("app.routers.scans.run_scan", new_callable=AsyncMock) as mock_run:
            resp = await client.post("/api/scans", json={"domain": self.HOMOGRAPH})
        assert resp.status_code == 409
        detail = resp.json()["detail"]
        assert detail["needs_confirmation"] is True
        assert "homograph" in detail["explanation"].lower()
        assert detail["domain"] == self.HOMOGRAPH
        assert detail["punycode"] == self.HOMOGRAPH_PUNYCODE
        # No scan created, no background task launched.
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
        # Legitimate IDN (CJK, non-confusable): no homograph signature, the scan
        # starts directly without a confirmation step.
        with patch("app.routers.scans.run_scan", new_callable=AsyncMock) as mock_run:
            resp = await client.post("/api/scans", json={"domain": "中国.com"})
        assert resp.status_code == 201
        assert resp.json()["domain"] == "xn--fiqs8s.com"
        mock_run.assert_called_once()
        assert await _count_rows(Scan) == 1


# ===================================================================
# POST /api/scans — E2E integration (real orchestrator)
# ===================================================================


class TestCreateScanE2E:
    async def test_full_flow_scan_to_completed(self, client):
        """API → orchestrator → fake scanners → DB → full response via GET."""
        scanners = [
            _FakeScanner("dns", 0.5, score=80, findings=[
                FindingData(severity="high", title="SPF missing", description="No SPF"),
            ]),
            _FakeScanner("tls", 0.5, score=100, findings=[]),
        ]
        resp = await _create_scan_with_orchestrator(client, "example.com", scanners)
        assert resp.status_code == 201
        scan_id = resp.json()["id"]

        # Re-read via the GET API to get the final state with modules and findings
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
        assert dns_mod["findings"][0]["title"] == "SPF missing"
        assert tls_mod["score"] == 100
        assert len(tls_mod["findings"]) == 0

    async def test_e2e_get_scan_returns_modules_and_findings(self, client):
        """GET /api/scans/{id} returns the modules and findings after execution."""
        scanners = [
            _FakeScanner("headers", 1.0, score=70, findings=[
                FindingData(severity="medium", title="CSP missing", description="No CSP"),
                FindingData(severity="low", title="Referrer-Policy", description="Missing"),
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
        """A scanner that crashes does not fail the whole scan."""
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
        """Check that remediation and raw_data flow through the whole chain."""
        scanners = [
            _FakeScanner("tls", 1.0, score=70, findings=[
                FindingData(
                    severity="critical",
                    title="Expired cert",
                    description="Expired 5 days ago",
                    remediation="Renew with Let's Encrypt",
                    raw_data='{"expired_days": 5}',
                ),
            ]),
        ]
        resp = await _create_scan_with_orchestrator(client, "expired.com", scanners)
        scan_id = resp.json()["id"]

        get_resp = await client.get(f"/api/scans/{scan_id}")
        finding = get_resp.json()["modules"][0]["findings"][0]
        assert finding["severity"] == "critical"
        assert finding["title"] == "Expired cert"
        assert finding["description"] == "Expired 5 days ago"
        assert finding["remediation"] == "Renew with Let's Encrypt"


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
        # ScanSummary does not contain modules
        assert "modules" not in scan

    async def test_list_scans_limited_to_50(self, client):
        """The API returns at most 50 scans even when there are more."""
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
        assert "not found" in resp.json()["detail"].lower()

    async def test_get_scan_with_completed_modules(self, client):
        """GET returns the modules and findings after E2E execution."""
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
        """DELETE also removes the associated ScanModule and Finding rows."""
        scanners = [_FakeScanner("s", 1.0, 80, [
            FindingData(severity="high", title="Issue", description="Desc"),
        ])]
        resp = await _create_scan_with_orchestrator(client, "example.com", scanners)
        scan_id = resp.json()["id"]

        # Check that there are modules and findings in the DB
        assert await _count_rows(ScanModule) >= 1
        assert await _count_rows(Finding) >= 1

        await client.delete(f"/api/scans/{scan_id}")

        # Everything is deleted in cascade
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
        await _mark_completed(scan_id)

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
        await _mark_completed(scan_id)

        with patch("app.routers.scans.run_scan", new_callable=AsyncMock):
            resp = await client.post(f"/api/scans/{scan_id}/rescan")
        assert resp.json()["domain"] == "test.org"

    async def test_rescan_rejected_while_in_progress(self, client):
        """A rescan of a scan that is still pending/running is rejected (409).

        Rescans are serialized per scan: while a scan or rescan of the same id is
        in flight, a second rescan must not start a concurrent run that could
        delete the modules out from under the running scanners.
        """
        create_resp = await _create_scan(client)
        scan_id = create_resp.json()["id"]
        # The freshly created scan is still "pending" (its run is in flight).

        with patch("app.routers.scans.run_scan", new_callable=AsyncMock):
            resp = await client.post(f"/api/scans/{scan_id}/rescan")
        assert resp.status_code == 409
        assert "in progress" in resp.json()["detail"].lower()

        # The scan is untouched: still pending, not reset by the rejected rescan.
        assert (await _get_scan_with_modules(scan_id)).status == "pending"


# ===================================================================
# POST /api/scans/{scan_id}/rescan — cascade integration
# ===================================================================


class TestRescanCascade:
    async def test_rescan_deletes_old_modules_and_findings(self, client):
        """The rescan deletes the old modules/findings then recreates them."""
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

        # Rescan with different scanners
        scanners_v2 = [
            _FakeScanner("dns", 0.5, score=90, findings=[
                FindingData(severity="low", title="New DNS note", description="V2"),
            ]),
            _FakeScanner("tls", 0.5, score=100, findings=[]),
        ]
        with patch("app.scanners.orchestrator.SCANNERS", scanners_v2):
            resp = await client.post(f"/api/scans/{scan_id}/rescan")
        assert resp.status_code == 200

        # V2 via GET API: old modules deleted, new ones created
        get_v2 = await client.get(f"/api/scans/{scan_id}")
        data_v2 = get_v2.json()
        assert data_v2["status"] == "completed"
        assert len(data_v2["modules"]) == 2

        new_module_ids = {m["id"] for m in data_v2["modules"]}
        assert old_module_ids.isdisjoint(new_module_ids), "V1 modules must be deleted"

        total_findings_v2 = sum(len(m["findings"]) for m in data_v2["modules"])
        assert total_findings_v2 == 1  # only the "New DNS note" finding remains

        dns_mod = next(m for m in data_v2["modules"] if m["name"] == "dns")
        assert dns_mod["findings"][0]["title"] == "New DNS note"

    async def test_rescan_old_findings_not_in_db(self, client):
        """Check that the old Finding rows are actually purged from the DB."""
        scanners_v1 = [
            _FakeScanner("s", 1.0, score=50, findings=[
                FindingData(severity="critical", title="Old critical", description="V1"),
            ]),
        ]
        resp = await _create_scan_with_orchestrator(client, "example.com", scanners_v1)
        scan_id = resp.json()["id"]

        # Count findings before rescan
        count_before = await _count_rows(Finding)
        assert count_before >= 1

        scanners_v2 = [_FakeScanner("s", 1.0, score=100, findings=[])]
        with patch("app.scanners.orchestrator.SCANNERS", scanners_v2):
            await client.post(f"/api/scans/{scan_id}/rescan")

        # No finding must remain for this scan
        async with _db.AsyncSessionLocal() as session:
            result = await session.execute(
                select(Finding)
                .join(ScanModule)
                .where(ScanModule.scan_id == scan_id)
            )
            findings = result.scalars().all()
        assert len(findings) == 0

    async def test_rescan_score_updates(self, client):
        """The rescan recomputes the score with the new results."""
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
        """The rescan does not create a new Scan, it reuses the same ID."""
        resp = await _create_scan(client)
        scan_id = resp.json()["id"]
        await _mark_completed(scan_id)

        with patch("app.routers.scans.run_scan", new_callable=AsyncMock):
            resp = await client.post(f"/api/scans/{scan_id}/rescan")
        assert resp.json()["id"] == scan_id
        assert await _count_rows(Scan) == 1

    async def test_rescan_timestamps_reset_and_updated(self, client):
        """started_at and completed_at are reset then set again."""
        scanners = [_FakeScanner("s", 1.0, score=80)]
        resp = await _create_scan_with_orchestrator(client, "example.com", scanners)
        scan_id = resp.json()["id"]

        scan_v1 = await _get_scan_with_modules(scan_id)
        v1_created = scan_v1.created_at

        scanners_v2 = [_FakeScanner("s", 1.0, score=90)]
        with patch("app.scanners.orchestrator.SCANNERS", scanners_v2):
            await client.post(f"/api/scans/{scan_id}/rescan")

        scan_v2 = await _get_scan_with_modules(scan_id)
        assert scan_v2.created_at >= v1_created  # created_at was refreshed by now_utc()
        assert scan_v2.started_at is not None
        assert scan_v2.completed_at is not None


# ===================================================================
# Rate limiting
# ===================================================================


class TestRateLimiting:
    async def test_create_scan_rate_limited_after_5(self, client_with_rate_limit):
        """POST /api/scans is limited to 5/minute."""
        c = client_with_rate_limit
        for i in range(5):
            with patch("app.routers.scans.run_scan", new_callable=AsyncMock):
                resp = await c.post("/api/scans", json={"domain": f"d{i}.com"})
            assert resp.status_code == 201, f"Request {i+1} should succeed"

        # The 6th request must be rejected
        with patch("app.routers.scans.run_scan", new_callable=AsyncMock):
            resp = await c.post("/api/scans", json={"domain": "one-too-many.com"})
        assert resp.status_code == 429

    async def test_rescan_rate_limited_after_5(self, client_with_rate_limit):
        """POST /api/scans/{id}/rescan is limited to 5/minute."""
        c = client_with_rate_limit

        # Create a scan (consumes 1 of the 5 creations)
        # Note: the rate limit is per endpoint AND a global default (30/min)
        # Create the scan without rate limit first
        limiter.enabled = False
        resp = await _create_scan(c)
        scan_id = resp.json()["id"]
        limiter.enabled = True

        for i in range(5):
            # ``run_scan`` is mocked, so the scan never leaves "pending" on its
            # own; put it back in a terminal state before each rescan so the
            # request reaches the handler (and counts against the rate limit).
            await _mark_completed(scan_id)
            with patch("app.routers.scans.run_scan", new_callable=AsyncMock):
                resp = await c.post(f"/api/scans/{scan_id}/rescan")
            assert resp.status_code == 200, f"Rescan {i+1} should succeed"

        await _mark_completed(scan_id)
        with patch("app.routers.scans.run_scan", new_callable=AsyncMock):
            resp = await c.post(f"/api/scans/{scan_id}/rescan")
        assert resp.status_code == 429

    async def test_get_and_list_not_rate_limited_at_5(self, client_with_rate_limit):
        """GET endpoints are not limited to 5/min (default 30/min)."""
        c = client_with_rate_limit
        for _ in range(10):
            resp = await c.get("/api/scans")
            assert resp.status_code == 200


# ===================================================================
# Concurrence
# ===================================================================


class TestConcurrency:
    async def test_concurrent_rescans_stay_consistent(self, client):
        """Two simultaneous rescans of the same scan must not corrupt it.

        Rescans are serialized per scan with an atomic claim on the scan status:
        exactly one of two overlapping rescans wins the claim and re-runs; the
        loser is rejected with 409 instead of deleting the modules the winner is
        recreating. The scan ends with exactly one module holding its findings
        once, and no request raises.
        """
        finding = FindingData(severity="high", title="Risky", description="Once")
        scanners = [_SlowScanner("s", 1.0, score=80, findings=[finding])]
        resp = await _create_scan_with_orchestrator(client, "example.com", scanners)
        scan_id = resp.json()["id"]

        async def rescan():
            return await client.post(f"/api/scans/{scan_id}/rescan")

        # Patch SCANNERS once, around both concurrent rescans. Patching the same
        # target inside each gathered task would overlap two unittest.mock.patch
        # contexts on one global: their save/restore is not concurrency-safe and
        # would leave SCANNERS permanently corrupted, leaking into later tests.
        with patch("app.scanners.orchestrator.SCANNERS",
                   [_SlowScanner("s", 1.0, score=90, findings=[finding])]):
            results = await asyncio.gather(
                rescan(),
                rescan(),
                return_exceptions=True,
            )

        # No exception escapes from either request (background tasks included).
        statuses = []
        for r in results:
            assert not isinstance(r, BaseException), f"Unexpected exception: {r!r}"
            statuses.append(r.status_code)
        # Exactly one rescan was accepted; the other lost the claim (409).
        assert sorted(statuses) == [200, 409]

        # The scan is still accessible and holds exactly one module — serializing
        # the rescans leaves no duplicated ``(scan_id, "s")`` rows behind.
        get_resp = await client.get(f"/api/scans/{scan_id}")
        assert get_resp.status_code == 200
        data = get_resp.json()
        assert data["status"] == "completed"
        assert len(data["modules"]) == 1
        assert data["modules"][0]["name"] == "s"
        # The single finding is persisted once, not duplicated by a second run.
        assert len(data["modules"][0]["findings"]) == 1

        async with _db.AsyncSessionLocal() as session:
            result = await session.execute(
                select(ScanModule)
                .options(selectinload(ScanModule.findings))
                .where(ScanModule.scan_id == scan_id)
            )
            modules = result.scalars().all()
        assert len(modules) == 1
        assert len(modules[0].findings) == 1

    async def test_staggered_rescan_during_scan_is_rejected(self, client):
        """A rescan firing *while the first run's scanners are mid-scan* must be
        rejected, not corrupt the in-flight run.

        This is the real-world case (rescans a few seconds apart): the first
        rescan resets the scan and its background run starts; its scanners suspend
        on network I/O; a second rescan then arrives. Without serialization the
        second rescan hard-deletes the modules the first run is still scanning, so
        when a runner commits its result it updates a now-deleted row and
        SQLAlchemy raises ``StaleDataError`` (surfacing as an HTTP 500 and a
        half-done run). Serializing rescans per scan rejects the mid-scan rescan
        with 409 and lets the first run finish cleanly.

        The scanner suspends for 0.5s; the second rescan is fired 0.1s in, while
        the first run is provably still mid-scan.
        """
        finding = FindingData(severity="high", title="Risky", description="Once")
        # Create + run an initial scan to completion so it can be rescanned.
        scanners = [_SlowScanner("s", 1.0, score=80, findings=[finding], delay=0.5)]
        resp = await _create_scan_with_orchestrator(client, "example.com", scanners)
        scan_id = resp.json()["id"]

        async def rescan():
            return await client.post(f"/api/scans/{scan_id}/rescan")

        with patch("app.scanners.orchestrator.SCANNERS",
                   [_SlowScanner("s", 1.0, score=90, findings=[finding], delay=0.5)]):
            # Fire the first rescan; its background run starts and its scanner
            # suspends mid-scan during the sleep below.
            first = asyncio.create_task(rescan())
            await asyncio.sleep(0.1)
            # Second rescan arrives while the first run is still scanning.
            second = await rescan()
            first_resp = await first

        # The first run completed cleanly (no StaleDataError surfacing as 500)...
        assert not isinstance(first_resp, BaseException), f"Unexpected: {first_resp!r}"
        assert first_resp.status_code == 200
        # ...and the mid-scan rescan was rejected instead of corrupting it.
        assert second.status_code == 409

        # Exactly one module with its finding once — the in-flight run was never
        # deleted out from under its scanners.
        get_resp = await client.get(f"/api/scans/{scan_id}")
        data = get_resp.json()
        assert data["status"] == "completed"
        assert len(data["modules"]) == 1
        assert data["modules"][0]["score"] == 90
        assert len(data["modules"][0]["findings"]) == 1

    async def test_concurrent_create_different_domains(self, client):
        """Concurrent creations on different domains do not interfere."""

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


# ===================================================================
# GET /api/scans/history — historical comparison (13.1)
# ===================================================================


async def _insert_scan(
    *,
    domain: str,
    created_at,
    score: int | None = None,
    grade: str | None = None,
    status: str = "completed",
    findings: list[tuple[str, str, str]] | None = None,
):
    """Insert a scan with its findings directly in DB.

    ``findings`` is a list of ``(module_name, severity, title)`` tuples; they are
    grouped per module. Returns the created scan id.
    """
    async with _db.AsyncSessionLocal() as session:
        scan = Scan(
            domain=domain,
            status=status,
            score=score,
            grade=grade,
            created_at=created_at,
        )
        session.add(scan)
        await session.flush()

        modules: dict[str, ScanModule] = {}
        for module_name, severity, title in findings or []:
            module = modules.get(module_name)
            if module is None:
                module = ScanModule(
                    scan_id=scan.id,
                    name=module_name,
                    weight=1.0,
                    status="completed",
                )
                session.add(module)
                await session.flush()
                modules[module_name] = module
            session.add(Finding(
                module_id=module.id,
                severity=severity,
                title=title,
                description=title,
            ))

        await session.commit()
        return scan.id


class TestScanHistory:
    async def test_history_unknown_domain_is_empty(self, client):
        resp = await client.get("/api/scans/history", params={"domain": "nope.com"})
        assert resp.status_code == 200
        assert resp.json() == []

    async def test_history_filtered_by_domain(self, client):
        from datetime import datetime, timezone

        base = datetime(2026, 1, 1, tzinfo=timezone.utc)
        await _insert_scan(domain="example.com", created_at=base)
        await _insert_scan(domain="example.com", created_at=base.replace(day=2))
        await _insert_scan(domain="other.com", created_at=base.replace(day=3))

        resp = await client.get("/api/scans/history", params={"domain": "example.com"})
        assert resp.status_code == 200
        data = resp.json()
        assert len(data) == 2
        assert all(s["domain"] == "example.com" for s in data)

    async def test_history_sorted_desc(self, client):
        from datetime import datetime, timezone

        base = datetime(2026, 1, 1, tzinfo=timezone.utc)
        await _insert_scan(domain="example.com", created_at=base, score=50, grade="F")
        await _insert_scan(
            domain="example.com", created_at=base.replace(day=5), score=90, grade="A"
        )
        await _insert_scan(
            domain="example.com", created_at=base.replace(day=3), score=70, grade="C"
        )

        resp = await client.get("/api/scans/history", params={"domain": "example.com"})
        data = resp.json()
        assert [s["score"] for s in data] == [90, 70, 50]

    async def test_history_returns_summary_fields(self, client):
        from datetime import datetime, timezone

        await _insert_scan(
            domain="example.com",
            created_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
            score=80,
            grade="B",
        )
        resp = await client.get("/api/scans/history", params={"domain": "example.com"})
        scan = resp.json()[0]
        assert set(scan) == {"id", "domain", "status", "score", "grade", "created_at"}


# ===================================================================
# GET /api/scans/{scan_id}/diff — diff between two scans (13.1)
# ===================================================================


class TestScanDiff:
    async def test_diff_scan_not_found(self, client):
        resp = await client.get("/api/scans/nope/diff")
        assert resp.status_code == 404
        assert "not found" in resp.json()["detail"].lower()

    async def test_diff_single_scan_has_no_previous(self, client):
        from datetime import datetime, timezone

        scan_id = await _insert_scan(
            domain="example.com",
            created_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
            score=80,
            grade="B",
            findings=[("headers", "medium", "Missing CSP")],
        )
        resp = await client.get(f"/api/scans/{scan_id}/diff")
        assert resp.status_code == 200
        data = resp.json()
        assert data["scan_id"] == scan_id
        assert data["previous_scan"] is None
        assert data["score_delta"] is None
        assert data["grade_change"] is None
        assert data["new_findings"] == []
        assert data["resolved_findings"] == []

    async def test_diff_against_previous_scan(self, client):
        from datetime import datetime, timezone

        base = datetime(2026, 1, 1, tzinfo=timezone.utc)
        await _insert_scan(
            domain="example.com",
            created_at=base,
            score=60,
            grade="D",
            findings=[
                ("headers", "high", "Missing HSTS"),
                ("dns", "medium", "No DMARC"),
            ],
        )
        current_id = await _insert_scan(
            domain="example.com",
            created_at=base.replace(day=2),
            score=80,
            grade="B",
            findings=[
                ("dns", "medium", "No DMARC"),
                ("tls", "low", "Weak cipher"),
            ],
        )

        resp = await client.get(f"/api/scans/{current_id}/diff")
        assert resp.status_code == 200
        data = resp.json()

        assert data["previous_scan"]["score"] == 60
        assert data["score_delta"] == 20
        assert data["grade_change"] == "D->B"

        new_titles = {(f["module"], f["title"]) for f in data["new_findings"]}
        resolved_titles = {(f["module"], f["title"]) for f in data["resolved_findings"]}
        assert new_titles == {("tls", "Weak cipher")}
        assert resolved_titles == {("headers", "Missing HSTS")}

    async def test_diff_same_title_different_module_is_distinct(self, client):
        """Finding identity is (module, title), not the title alone."""
        from datetime import datetime, timezone

        base = datetime(2026, 1, 1, tzinfo=timezone.utc)
        await _insert_scan(
            domain="example.com",
            created_at=base,
            score=70,
            grade="C",
            findings=[("headers", "low", "Issue")],
        )
        current_id = await _insert_scan(
            domain="example.com",
            created_at=base.replace(day=2),
            score=70,
            grade="C",
            findings=[("dns", "low", "Issue")],
        )

        resp = await client.get(f"/api/scans/{current_id}/diff")
        data = resp.json()
        assert {(f["module"], f["title"]) for f in data["new_findings"]} == {
            ("dns", "Issue")
        }
        assert {(f["module"], f["title"]) for f in data["resolved_findings"]} == {
            ("headers", "Issue")
        }
        # Same grade on both scans → no grade_change reported.
        assert data["grade_change"] is None
        assert data["score_delta"] == 0

    async def test_diff_against_explicit_scan_id(self, client):
        from datetime import datetime, timezone

        base = datetime(2026, 1, 1, tzinfo=timezone.utc)
        oldest_id = await _insert_scan(
            domain="example.com",
            created_at=base,
            score=40,
            grade="F",
            findings=[("dns", "high", "No SPF")],
        )
        # An intermediate scan that would be the default "previous".
        await _insert_scan(
            domain="example.com",
            created_at=base.replace(day=2),
            score=55,
            grade="F",
            findings=[("dns", "high", "No SPF")],
        )
        current_id = await _insert_scan(
            domain="example.com",
            created_at=base.replace(day=3),
            score=90,
            grade="A",
            findings=[],
        )

        resp = await client.get(
            f"/api/scans/{current_id}/diff", params={"against": oldest_id}
        )
        data = resp.json()
        assert data["previous_scan"]["id"] == oldest_id
        assert data["score_delta"] == 50
        assert {(f["module"], f["title"]) for f in data["resolved_findings"]} == {
            ("dns", "No SPF")
        }

    async def test_diff_against_unknown_scan_is_404(self, client):
        from datetime import datetime, timezone

        scan_id = await _insert_scan(
            domain="example.com",
            created_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
        )
        resp = await client.get(
            f"/api/scans/{scan_id}/diff", params={"against": "nope"}
        )
        assert resp.status_code == 404

    async def test_diff_score_delta_absent_when_scores_missing(self, client):
        from datetime import datetime, timezone

        base = datetime(2026, 1, 1, tzinfo=timezone.utc)
        await _insert_scan(
            domain="example.com", created_at=base, status="failed", score=None
        )
        current_id = await _insert_scan(
            domain="example.com", created_at=base.replace(day=2), status="failed",
            score=None,
        )
        resp = await client.get(f"/api/scans/{current_id}/diff")
        data = resp.json()
        assert data["previous_scan"] is not None
        assert data["score_delta"] is None
