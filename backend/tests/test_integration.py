"""End-to-end integration tests.

Verifies the full flow:
  API request → Orchestrator → Real scanners → Parsing → DB → API response

Only network I/O is mocked (DNS, SSL, HTTP, socket).
The real scanners, the real orchestrator and the real DB are used.
"""

import pytest
from unittest.mock import patch, AsyncMock, MagicMock
from datetime import datetime, timezone, timedelta

import dns.asyncresolver
import dns.resolver
import httpx
import respx
from httpx import ASGITransport, AsyncClient

from app.main import app
from app.limiter import limiter
from app.models import Scan, ScanModule, Finding


# ===================================================================
# Fixtures
# ===================================================================


@pytest.fixture(autouse=True)
async def _setup_db(isolated_db):
    """Each test gets a private SQLite file + fresh engine (see conftest)."""
    yield


@pytest.fixture
async def client():
    """ASGI HTTP client without rate limiting, BackgroundTasks neutralized."""
    limiter.enabled = False
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as c:
        # Neutralize BackgroundTasks to control the execution of run_scan
        with patch("app.routers.scans.BackgroundTasks.add_task"):
            yield c
    limiter.enabled = True


@pytest.fixture(autouse=True)
def _no_external_io():
    """Cut the network paths the per-test patches do not cover.

    The mocked DNS resolver only covers the dns scanner module: the SMTP
    STARTTLS probe (real DNS lookups + outbound port-25 connections), the
    SURBL/URIBL and PhishTank reputation lookups and the hstspreload.org API
    call would otherwise hit the real network. Each is forced to its
    indeterminate / no-op outcome so the suite passes with the network
    unplugged.
    """
    from app.scanners.dns import MxProbeResult

    with (
        patch(
            "app.scanners.dns._probe_starttls",
            return_value=MxProbeResult(starttls=None),
        ),
        patch("app.scanners.reputation._check_surbl_uribl", new_callable=AsyncMock),
        patch("app.scanners.reputation._check_phishtank", new_callable=AsyncMock),
        patch(
            "app.scanners.tls._check_hsts_preload",
            new_callable=AsyncMock,
            return_value=[],
        ),
    ):
        yield


# ===================================================================
# Helpers to mock the network layers
# ===================================================================


def _dns_mock():
    """Return a DNS mock that simulates a well-configured domain."""
    resolver = AsyncMock(spec=dns.asyncresolver.Resolver)
    resolver.nameservers = ["8.8.8.8"]

    class FakeRecord:
        def __init__(self, text):
            self._text = text
        def to_text(self):
            return self._text

    class FakeMx:
        def __init__(self, host):
            self.exchange = MagicMock()
            self.exchange.__str__ = MagicMock(return_value=host)
            self.preference = 10

    async def fake_resolve(name, rdtype):
        if rdtype == "TXT":
            if name.startswith("_dmarc."):
                return [FakeRecord('"v=DMARC1; p=reject; rua=mailto:d@test.com"')]
            if name.startswith("_mta-sts."):
                raise dns.resolver.NoAnswer()
            if "_domainkey" in name:
                if name.startswith("default._domainkey"):
                    return [FakeRecord('"v=DKIM1; k=rsa; p=ABC"')]
                raise dns.resolver.NXDOMAIN()
            # TXT of the main domain → SPF
            return [FakeRecord('"v=spf1 include:_spf.google.com ~all"')]
        if rdtype == "DNSKEY":
            raise dns.resolver.NoAnswer()
        if rdtype == "MX":
            return [FakeMx("mail.test.com.")]
        if rdtype == "CAA":
            return [FakeRecord('0 issue "letsencrypt.org"')]
        if rdtype == "TLSA":
            raise dns.resolver.NXDOMAIN()
        raise dns.resolver.NoAnswer()

    resolver.resolve = AsyncMock(side_effect=fake_resolve)
    return resolver


def _ssl_mock_context():
    """Return the patches to simulate a healthy TLS connection."""
    from tests.conftest import make_cert_info

    cert_info = make_cert_info(
        not_after=datetime.now(timezone.utc) + timedelta(days=90),
        issuer_cn="Let's Encrypt Authority X3",
        subject_cn="integration-test.com",
        key_type="RSA",
        key_size=2048,
        sig_algo="sha256",
        protocol="TLSv1.3",
        cipher="TLS_AES_256_GCM_SHA384",
        verified=True,
        sans=["integration-test.com", "www.integration-test.com"],
    )
    return cert_info


def _reputation_patches():
    """Patches for the reputation scanner: socket + no API key."""
    return {
        "resolve_ips": patch(
            "app.scanners.reputation._resolve_ips",
            return_value=["93.184.216.34"],
        ),
        "spamhaus": patch(
            "app.scanners.reputation._check_spamhaus_dns",
        ),
        "env_key": patch.dict("os.environ", {"ABUSEIPDB_API_KEY": ""}, clear=False),
    }


# ===================================================================
# Integration test: full flow with all the real scanners
# ===================================================================


class TestFullIntegration:
    """Flow API request → Orchestrator → 7 real scanners → DB → API GET."""

    async def test_full_scan_flow_with_real_scanners(self, client):
        """
        Create a scan via the API, run the real orchestrator with the real
        scanners (network mocked), then verify the GET response.
        """
        dns_resolver = _dns_mock()
        cert_info = _ssl_mock_context()
        rep_patches = _reputation_patches()

        # Secure HTTP headers
        secure_headers = {
            "strict-transport-security": "max-age=31536000",
            "content-security-policy": "default-src 'self'",
            "x-frame-options": "DENY",
            "x-content-type-options": "nosniff",
            "referrer-policy": "strict-origin-when-cross-origin",
            "permissions-policy": "camera=()",
            "cross-origin-opener-policy": "same-origin",
            "cross-origin-embedder-policy": "require-corp",
            "cross-origin-resource-policy": "same-origin",
        }

        with (
            # DNS: mock the Resolver constructor
            patch("app.scanners.dns.dns.asyncresolver.Resolver", return_value=dns_resolver),
            # TLS: mock _get_cert_info
            patch("app.scanners.tls._get_cert_info", new_callable=AsyncMock, return_value=cert_info),
            # TLS: testssl not available
            patch("app.scanners.testssl_runner.is_available", return_value=False),
            # Reputation
            rep_patches["resolve_ips"],
            rep_patches["spamhaus"],
            rep_patches["env_key"],
            # Subdomains: no subdomains
            patch("app.scanners.subdomains._fetch_subdomains", new_callable=AsyncMock, return_value=set()),
            # Ports: nmap not available + whois mocked
            patch("app.scanners.ports.is_available", return_value=False),
            patch("app.scanners.ports._check_whois", new_callable=AsyncMock),
            # Leaks + Headers: mock HTTP via respx
            respx.mock,
        ):
            # HIBP: no breach
            respx.get(url__regex=r".*haveibeenpwned.*").mock(
                return_value=httpx.Response(404)
            )
            # Headers: page with secure headers
            respx.get(url__regex=r"https://integration-test\.com.*").mock(
                return_value=httpx.Response(
                    200,
                    headers=secure_headers,
                    text="<html><head></head><body>OK</body></html>",
                )
            )
            respx.get(url__regex=r"http://integration-test\.com.*").mock(
                return_value=httpx.Response(200)
            )

            # 1. Create the scan via the API
            resp = await client.post("/api/scans", json={"domain": "integration-test.com"})
            assert resp.status_code == 201
            scan_id = resp.json()["id"]
            assert resp.json()["status"] == "pending"
            assert resp.json()["domain"] == "integration-test.com"

            # 2. Run the orchestrator directly (BackgroundTasks does not run in the tests)
            from app.scanners.orchestrator import run_scan
            await run_scan(scan_id, "integration-test.com")

            # 3. GET the completed scan
            resp = await client.get(f"/api/scans/{scan_id}")
            assert resp.status_code == 200
            data = resp.json()

        # --- Structural checks ---

        # Status and score
        assert data["status"] == "completed"
        assert data["score"] is not None
        assert 0 <= data["score"] <= 100
        assert data["grade"] in ("A", "B", "C", "D", "F")
        assert data["started_at"] is not None
        assert data["completed_at"] is not None

        # 6 modules created (one per scanner)
        modules = data["modules"]
        assert len(modules) == 7
        module_names = {m["name"] for m in modules}
        assert module_names == {"dns", "tls", "headers", "reputation", "subdomains", "leaks", "ports"}

        # Each module has a score, a completed status, and timestamps
        for m in modules:
            assert m["status"] == "completed", f"Module {m['name']} not completed: {m['status']}"
            assert m["score"] is not None, f"Module {m['name']} has no score"
            assert 0 <= m["score"] <= 100
            assert m["weight"] > 0

        # The findings are objects with the right fields
        all_findings = []
        for m in modules:
            for f in m["findings"]:
                assert "severity" in f
                assert "title" in f
                assert "description" in f
                assert f["severity"] in ("critical", "high", "medium", "low", "info")
                all_findings.append(f)

        # The global score is consistent with the weighting formula
        total_weight = sum(m["weight"] for m in modules)
        expected_score = round(
            sum(m["score"] * m["weight"] for m in modules) / total_weight
        )
        assert data["score"] == expected_score

    async def test_full_scan_with_findings_persisted(self, client):
        """
        Scenario with a misconfigured domain — verifies that the findings
        are correctly persisted and returned via the API.
        """
        dns_resolver = _dns_mock()

        # Modified DNS mock: no SPF
        original_resolve = dns_resolver.resolve.side_effect

        async def bad_dns_resolve(name, rdtype):
            if rdtype == "TXT" and not name.startswith("_"):
                # No SPF
                class FakeRecord:
                    def to_text(self):
                        return '"some-other-txt-record"'
                return [FakeRecord()]
            return await original_resolve(name, rdtype)

        dns_resolver.resolve = AsyncMock(side_effect=bad_dns_resolve)

        # TLS: expired cert
        from tests.conftest import make_cert_info
        expired_cert = make_cert_info(
            not_after=datetime.now(timezone.utc) - timedelta(days=5),
            issuer_cn="Expired CA",
            subject_cn="bad-domain.com",
        )

        rep_patches = _reputation_patches()

        with (
            patch("app.scanners.dns.dns.asyncresolver.Resolver", return_value=dns_resolver),
            patch("app.scanners.tls._get_cert_info", new_callable=AsyncMock, return_value=expired_cert),
            patch("app.scanners.testssl_runner.is_available", return_value=False),
            rep_patches["resolve_ips"],
            rep_patches["spamhaus"],
            rep_patches["env_key"],
            patch("app.scanners.subdomains._fetch_subdomains", new_callable=AsyncMock, return_value=set()),
            patch("app.scanners.ports.is_available", return_value=False),
            patch("app.scanners.ports._check_whois", new_callable=AsyncMock),
            respx.mock,
        ):
            respx.get(url__regex=r".*haveibeenpwned.*").mock(
                return_value=httpx.Response(404)
            )
            # Headers: no security header
            respx.get(url__regex=r"https://bad-domain\.com.*").mock(
                return_value=httpx.Response(200, text="<html></html>")
            )
            respx.get(url__regex=r"http://bad-domain\.com.*").mock(
                return_value=httpx.Response(200)
            )

            resp = await client.post("/api/scans", json={"domain": "bad-domain.com"})
            scan_id = resp.json()["id"]

            from app.scanners.orchestrator import run_scan
            await run_scan(scan_id, "bad-domain.com")

            resp = await client.get(f"/api/scans/{scan_id}")
            data = resp.json()

        assert data["status"] == "completed"
        # Score must be < 100 (expired cert = critical, missing headers, missing SPF)
        assert data["score"] < 100

        # Check specific findings
        all_findings = []
        for m in data["modules"]:
            all_findings.extend(m["findings"])

        titles = [f["title"] for f in all_findings]

        # Expired cert → critical finding
        assert any("expired" in t.lower() for t in titles), f"No expired cert finding in {titles}"
        # Missing SPF → finding
        assert any("SPF" in t for t in titles), f"No SPF finding in {titles}"
        # Missing security headers → findings
        assert any("HSTS" in t for t in titles), f"No HSTS finding in {titles}"

        # Each finding has a non-empty description
        for f in all_findings:
            assert len(f["description"]) > 0

    async def test_list_endpoint_returns_completed_scan(self, client):
        """After a full scan, GET /api/scans lists it correctly."""
        dns_resolver = _dns_mock()
        cert_info = _ssl_mock_context()
        rep_patches = _reputation_patches()

        with (
            patch("app.scanners.dns.dns.asyncresolver.Resolver", return_value=dns_resolver),
            patch("app.scanners.tls._get_cert_info", new_callable=AsyncMock, return_value=cert_info),
            patch("app.scanners.testssl_runner.is_available", return_value=False),
            rep_patches["resolve_ips"],
            rep_patches["spamhaus"],
            rep_patches["env_key"],
            patch("app.scanners.subdomains._fetch_subdomains", new_callable=AsyncMock, return_value=set()),
            patch("app.scanners.ports.is_available", return_value=False),
            patch("app.scanners.ports._check_whois", new_callable=AsyncMock),
            respx.mock,
        ):
            respx.get(url__regex=r".*haveibeenpwned.*").mock(
                return_value=httpx.Response(404)
            )
            respx.get(url__regex=r"https://list-test\.com.*").mock(
                return_value=httpx.Response(200, text="<html></html>")
            )
            respx.get(url__regex=r"http://list-test\.com.*").mock(
                return_value=httpx.Response(200)
            )

            resp = await client.post("/api/scans", json={"domain": "list-test.com"})
            scan_id = resp.json()["id"]

            from app.scanners.orchestrator import run_scan
            await run_scan(scan_id, "list-test.com")

            # GET /api/scans — the scan must appear in the list
            resp = await client.get("/api/scans")
            assert resp.status_code == 200
            scans = resp.json()
            assert len(scans) >= 1
            found = [s for s in scans if s["id"] == scan_id]
            assert len(found) == 1
            assert found[0]["status"] == "completed"
            assert found[0]["domain"] == "list-test.com"
            assert found[0]["score"] is not None

    async def test_rescan_replaces_modules_and_findings(self, client):
        """The rescan deletes the old modules/findings and creates new ones."""
        dns_resolver = _dns_mock()
        cert_info = _ssl_mock_context()
        rep_patches = _reputation_patches()

        with (
            patch("app.scanners.dns.dns.asyncresolver.Resolver", return_value=dns_resolver),
            patch("app.scanners.tls._get_cert_info", new_callable=AsyncMock, return_value=cert_info),
            patch("app.scanners.testssl_runner.is_available", return_value=False),
            rep_patches["resolve_ips"],
            rep_patches["spamhaus"],
            rep_patches["env_key"],
            patch("app.scanners.subdomains._fetch_subdomains", new_callable=AsyncMock, return_value=set()),
            patch("app.scanners.ports.is_available", return_value=False),
            patch("app.scanners.ports._check_whois", new_callable=AsyncMock),
            respx.mock,
        ):
            respx.get(url__regex=r".*haveibeenpwned.*").mock(
                return_value=httpx.Response(404)
            )
            respx.get(url__regex=r"https://rescan-test\.com.*").mock(
                return_value=httpx.Response(200, text="<html></html>")
            )
            respx.get(url__regex=r"http://rescan-test\.com.*").mock(
                return_value=httpx.Response(200)
            )

            # First scan
            resp = await client.post("/api/scans", json={"domain": "rescan-test.com"})
            scan_id = resp.json()["id"]

            from app.scanners.orchestrator import run_scan
            await run_scan(scan_id, "rescan-test.com")

            resp = await client.get(f"/api/scans/{scan_id}")
            first_data = resp.json()
            first_module_ids = {m["id"] for m in first_data["modules"]}

            # Rescan
            resp = await client.post(f"/api/scans/{scan_id}/rescan")
            assert resp.status_code == 200

            await run_scan(scan_id, "rescan-test.com")

            resp = await client.get(f"/api/scans/{scan_id}")
            second_data = resp.json()
            second_module_ids = {m["id"] for m in second_data["modules"]}

        # Same scan_id, same domain
        assert second_data["id"] == scan_id
        assert second_data["domain"] == "rescan-test.com"
        assert second_data["status"] == "completed"

        # The modules are new (different IDs)
        assert first_module_ids.isdisjoint(second_module_ids)
        assert len(second_data["modules"]) == 7

    async def test_scanner_failure_handled_in_full_flow(self, client):
        """A scanner that crashes does not prevent the others from completing."""
        dns_resolver = _dns_mock()
        cert_info = _ssl_mock_context()
        rep_patches = _reputation_patches()

        with (
            patch("app.scanners.dns.dns.asyncresolver.Resolver", return_value=dns_resolver),
            # TLS crashes
            patch("app.scanners.tls._get_cert_info", new_callable=AsyncMock,
                  side_effect=Exception("TLS scanner crashed")),
            patch("app.scanners.testssl_runner.is_available", return_value=False),
            rep_patches["resolve_ips"],
            rep_patches["spamhaus"],
            rep_patches["env_key"],
            patch("app.scanners.subdomains._fetch_subdomains", new_callable=AsyncMock, return_value=set()),
            patch("app.scanners.ports.is_available", return_value=False),
            patch("app.scanners.ports._check_whois", new_callable=AsyncMock),
            respx.mock,
        ):
            respx.get(url__regex=r".*haveibeenpwned.*").mock(
                return_value=httpx.Response(404)
            )
            respx.get(url__regex=r"https://crash-test\.com.*").mock(
                return_value=httpx.Response(200, text="<html></html>")
            )
            respx.get(url__regex=r"http://crash-test\.com.*").mock(
                return_value=httpx.Response(200)
            )

            resp = await client.post("/api/scans", json={"domain": "crash-test.com"})
            scan_id = resp.json()["id"]

            from app.scanners.orchestrator import run_scan
            await run_scan(scan_id, "crash-test.com")

            resp = await client.get(f"/api/scans/{scan_id}")
            data = resp.json()

        assert data["status"] == "completed"
        modules_by_name = {m["name"]: m for m in data["modules"]}

        # TLS is in error — the base scanner catches the exception and returns a critical finding
        tls = modules_by_name["tls"]
        assert tls["status"] == "completed"
        # The TLS scanner handles the exception with a "Connexion TLS impossible" finding
        tls_findings = tls["findings"]
        assert len(tls_findings) >= 1
        assert any("TLS" in f["title"] or "impossible" in f["title"].lower() for f in tls_findings)

        # The other scanners completed normally
        for name in ("dns", "headers", "reputation", "subdomains", "leaks", "ports"):
            assert modules_by_name[name]["status"] == "completed"
            assert modules_by_name[name]["score"] is not None

    async def test_delete_scan_removes_everything(self, client):
        """DELETE /api/scans/{id} deletes scan + modules + findings (cascade)."""
        dns_resolver = _dns_mock()
        cert_info = _ssl_mock_context()
        rep_patches = _reputation_patches()

        with (
            patch("app.scanners.dns.dns.asyncresolver.Resolver", return_value=dns_resolver),
            patch("app.scanners.tls._get_cert_info", new_callable=AsyncMock, return_value=cert_info),
            patch("app.scanners.testssl_runner.is_available", return_value=False),
            rep_patches["resolve_ips"],
            rep_patches["spamhaus"],
            rep_patches["env_key"],
            patch("app.scanners.subdomains._fetch_subdomains", new_callable=AsyncMock, return_value=set()),
            patch("app.scanners.ports.is_available", return_value=False),
            patch("app.scanners.ports._check_whois", new_callable=AsyncMock),
            respx.mock,
        ):
            respx.get(url__regex=r".*haveibeenpwned.*").mock(
                return_value=httpx.Response(404)
            )
            respx.get(url__regex=r"https://delete-test\.com.*").mock(
                return_value=httpx.Response(200, text="<html></html>")
            )
            respx.get(url__regex=r"http://delete-test\.com.*").mock(
                return_value=httpx.Response(200)
            )

            resp = await client.post("/api/scans", json={"domain": "delete-test.com"})
            scan_id = resp.json()["id"]

            from app.scanners.orchestrator import run_scan
            await run_scan(scan_id, "delete-test.com")

            # Confirm that the scan exists
            resp = await client.get(f"/api/scans/{scan_id}")
            assert resp.status_code == 200
            assert len(resp.json()["modules"]) == 7

            # Delete
            resp = await client.delete(f"/api/scans/{scan_id}")
            assert resp.status_code == 204

            # The scan no longer exists
            resp = await client.get(f"/api/scans/{scan_id}")
            assert resp.status_code == 404

    async def test_finding_fields_survive_serialization(self, client):
        """
        Verify that the FindingData fields (severity, title, description,
        remediation) survive the path Scanner → DB → API JSON.
        """
        dns_resolver = _dns_mock()
        rep_patches = _reputation_patches()

        # Expired cert to force a finding with non-null remediation
        from tests.conftest import make_cert_info
        expired_cert = make_cert_info(
            not_after=datetime.now(timezone.utc) - timedelta(days=5),
        )

        with (
            patch("app.scanners.dns.dns.asyncresolver.Resolver", return_value=dns_resolver),
            patch("app.scanners.tls._get_cert_info", new_callable=AsyncMock, return_value=expired_cert),
            patch("app.scanners.testssl_runner.is_available", return_value=False),
            rep_patches["resolve_ips"],
            rep_patches["spamhaus"],
            rep_patches["env_key"],
            patch("app.scanners.subdomains._fetch_subdomains", new_callable=AsyncMock, return_value=set()),
            patch("app.scanners.ports.is_available", return_value=False),
            patch("app.scanners.ports._check_whois", new_callable=AsyncMock),
            respx.mock,
        ):
            respx.get(url__regex=r".*haveibeenpwned.*").mock(
                return_value=httpx.Response(404)
            )
            respx.get(url__regex=r"https://fields-test\.com.*").mock(
                return_value=httpx.Response(200, text="<html></html>")
            )
            respx.get(url__regex=r"http://fields-test\.com.*").mock(
                return_value=httpx.Response(200)
            )

            resp = await client.post("/api/scans", json={"domain": "fields-test.com"})
            scan_id = resp.json()["id"]

            from app.scanners.orchestrator import run_scan
            await run_scan(scan_id, "fields-test.com")

            resp = await client.get(f"/api/scans/{scan_id}")
            data = resp.json()

        # Find the "TLS certificate expired" finding
        tls_module = next(m for m in data["modules"] if m["name"] == "tls")
        expired_finding = next(
            (f for f in tls_module["findings"] if "expired" in f["title"].lower()),
            None,
        )

        assert expired_finding is not None
        assert expired_finding["severity"] == "critical"
        assert expired_finding["title"] == "TLS certificate expired"
        assert "expired" in expired_finding["description"]
        assert expired_finding["remediation"] is not None
        assert "renew" in expired_finding["remediation"].lower()

    async def test_weighted_score_calculation_end_to_end(self, client):
        """
        Verify that the global score is indeed the weighted average of the modules,
        computed by the orchestrator and returned by the API.
        """
        dns_resolver = _dns_mock()
        cert_info = _ssl_mock_context()
        rep_patches = _reputation_patches()

        with (
            patch("app.scanners.dns.dns.asyncresolver.Resolver", return_value=dns_resolver),
            patch("app.scanners.tls._get_cert_info", new_callable=AsyncMock, return_value=cert_info),
            patch("app.scanners.testssl_runner.is_available", return_value=False),
            rep_patches["resolve_ips"],
            rep_patches["spamhaus"],
            rep_patches["env_key"],
            patch("app.scanners.subdomains._fetch_subdomains", new_callable=AsyncMock, return_value=set()),
            patch("app.scanners.ports.is_available", return_value=False),
            patch("app.scanners.ports._check_whois", new_callable=AsyncMock),
            respx.mock,
        ):
            respx.get(url__regex=r".*haveibeenpwned.*").mock(
                return_value=httpx.Response(404)
            )
            respx.get(url__regex=r"https://score-test\.com.*").mock(
                return_value=httpx.Response(200, text="<html></html>")
            )
            respx.get(url__regex=r"http://score-test\.com.*").mock(
                return_value=httpx.Response(200)
            )

            resp = await client.post("/api/scans", json={"domain": "score-test.com"})
            scan_id = resp.json()["id"]

            from app.scanners.orchestrator import run_scan
            await run_scan(scan_id, "score-test.com")

            resp = await client.get(f"/api/scans/{scan_id}")
            data = resp.json()

        modules = data["modules"]
        total_weight = sum(m["weight"] for m in modules)
        expected = round(sum(m["score"] * m["weight"] for m in modules) / total_weight)

        assert data["score"] == expected

        # The grade matches the score
        from app.scanners.orchestrator import score_to_grade
        assert data["grade"] == score_to_grade(data["score"])
