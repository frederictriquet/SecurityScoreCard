"""Tests d'intégration bout-en-bout.

Vérifie le flux complet :
  Requête API → Orchestrateur → Scanners réels → Parsing → DB → Réponse API

Seules les E/S réseau sont mockées (DNS, SSL, HTTP, socket).
Les vrais scanners, le vrai orchestrateur et la vraie DB sont utilisés.
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
from app.models import Scan, ScanModule, Finding, Base
import app.database as _db


# ===================================================================
# Fixtures
# ===================================================================


@pytest.fixture(autouse=True)
async def _setup_db():
    """Crée et nettoie les tables pour chaque test."""
    async with _db.engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield
    async with _db.engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)


@pytest.fixture
async def client():
    """Client HTTP ASGI sans rate limiting, BackgroundTasks neutralisé."""
    limiter.enabled = False
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as c:
        # Neutraliser BackgroundTasks pour contrôler l'exécution de run_scan
        with patch("app.routers.scans.BackgroundTasks.add_task"):
            yield c
    limiter.enabled = True


# ===================================================================
# Helpers pour mocker les couches réseau
# ===================================================================


def _dns_mock():
    """Retourne un mock DNS qui simule un domaine bien configuré."""
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
            self.exchange.__str__ = lambda s: host
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
            # TXT du domaine principal → SPF
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
    """Retourne les patchs pour simuler une connexion TLS saine."""
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
    )
    return cert_info


def _reputation_patches():
    """Patches pour le scanner reputation : socket + pas d'API key."""
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
# Test d'intégration : flux complet avec tous les scanners réels
# ===================================================================


class TestFullIntegration:
    """Flux Requête API → Orchestrateur → 6 Scanners réels → DB → API GET."""

    async def test_full_scan_flow_with_real_scanners(self, client):
        """
        Crée un scan via l'API, exécute le vrai orchestrateur avec les vrais
        scanners (réseau mocké), puis vérifie la réponse GET.
        """
        dns_resolver = _dns_mock()
        cert_info = _ssl_mock_context()
        rep_patches = _reputation_patches()

        # Headers HTTP sécurisés
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
            # DNS : mock le constructeur du Resolver
            patch("app.scanners.dns.dns.asyncresolver.Resolver", return_value=dns_resolver),
            # TLS : mock _get_cert_info
            patch("app.scanners.tls._get_cert_info", new_callable=AsyncMock, return_value=cert_info),
            # TLS : testssl non disponible
            patch("app.scanners.testssl_runner.is_available", return_value=False),
            # Reputation
            rep_patches["resolve_ips"],
            rep_patches["spamhaus"],
            rep_patches["env_key"],
            # Subdomains : pas de sous-domaines
            patch("app.scanners.subdomains._fetch_subdomains", new_callable=AsyncMock, return_value=set()),
            # Leaks + Headers : mock HTTP via respx
            respx.mock,
        ):
            # HIBP : aucune breach
            respx.get(url__regex=r".*haveibeenpwned.*").mock(
                return_value=httpx.Response(404)
            )
            # Headers : page avec headers sécurisés
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

            # 1. Créer le scan via l'API
            resp = await client.post("/api/scans", json={"domain": "integration-test.com"})
            assert resp.status_code == 201
            scan_id = resp.json()["id"]
            assert resp.json()["status"] == "pending"
            assert resp.json()["domain"] == "integration-test.com"

            # 2. Exécuter l'orchestrateur directement (BackgroundTasks ne s'exécute pas dans les tests)
            from app.scanners.orchestrator import run_scan
            await run_scan(scan_id, "integration-test.com")

            # 3. GET le scan complété
            resp = await client.get(f"/api/scans/{scan_id}")
            assert resp.status_code == 200
            data = resp.json()

        # --- Vérifications structurelles ---

        # Statut et score
        assert data["status"] == "completed"
        assert data["score"] is not None
        assert 0 <= data["score"] <= 100
        assert data["grade"] in ("A", "B", "C", "D", "F")
        assert data["started_at"] is not None
        assert data["completed_at"] is not None

        # 6 modules créés (un par scanner)
        modules = data["modules"]
        assert len(modules) == 6
        module_names = {m["name"] for m in modules}
        assert module_names == {"dns", "tls", "headers", "reputation", "subdomains", "leaks"}

        # Chaque module a un score, un statut completed, et des timestamps
        for m in modules:
            assert m["status"] == "completed", f"Module {m['name']} not completed: {m['status']}"
            assert m["score"] is not None, f"Module {m['name']} has no score"
            assert 0 <= m["score"] <= 100
            assert m["weight"] > 0

        # Les findings sont des objets avec les bons champs
        all_findings = []
        for m in modules:
            for f in m["findings"]:
                assert "severity" in f
                assert "title" in f
                assert "description" in f
                assert f["severity"] in ("critical", "high", "medium", "low", "info")
                all_findings.append(f)

        # Le score global est cohérent avec la formule de pondération
        total_weight = sum(m["weight"] for m in modules)
        expected_score = round(
            sum(m["score"] * m["weight"] for m in modules) / total_weight
        )
        assert data["score"] == expected_score

    async def test_full_scan_with_findings_persisted(self, client):
        """
        Scénario avec un domaine mal configuré — vérifie que les findings
        sont correctement persistés et retournés via l'API.
        """
        dns_resolver = _dns_mock()

        # DNS mock modifié : pas de SPF
        original_resolve = dns_resolver.resolve.side_effect

        async def bad_dns_resolve(name, rdtype):
            if rdtype == "TXT" and not name.startswith("_"):
                # Pas de SPF
                class FakeRecord:
                    def to_text(self):
                        return '"some-other-txt-record"'
                return [FakeRecord()]
            return await original_resolve(name, rdtype)

        dns_resolver.resolve = AsyncMock(side_effect=bad_dns_resolve)

        # TLS : cert expiré
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
            respx.mock,
        ):
            respx.get(url__regex=r".*haveibeenpwned.*").mock(
                return_value=httpx.Response(404)
            )
            # Headers : aucun header de sécurité
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
        # Score doit être < 100 (cert expiré = critical, headers manquants, SPF manquant)
        assert data["score"] < 100

        # Vérifier des findings spécifiques
        all_findings = []
        for m in data["modules"]:
            all_findings.extend(m["findings"])

        titles = [f["title"] for f in all_findings]

        # Cert expiré → finding critique
        assert any("expiré" in t.lower() for t in titles), f"No expired cert finding in {titles}"
        # SPF manquant → finding
        assert any("SPF" in t for t in titles), f"No SPF finding in {titles}"
        # Headers de sécurité manquants → findings
        assert any("HSTS" in t for t in titles), f"No HSTS finding in {titles}"

        # Chaque finding a une description non vide
        for f in all_findings:
            assert len(f["description"]) > 0

    async def test_list_endpoint_returns_completed_scan(self, client):
        """Après un scan complet, GET /api/scans le liste correctement."""
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

            # GET /api/scans — le scan doit apparaître dans la liste
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
        """Le rescan supprime les anciens modules/findings et en crée de nouveaux."""
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

            # Premier scan
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

        # Même scan_id, même domain
        assert second_data["id"] == scan_id
        assert second_data["domain"] == "rescan-test.com"
        assert second_data["status"] == "completed"

        # Les modules sont nouveaux (IDs différents)
        assert first_module_ids.isdisjoint(second_module_ids)
        assert len(second_data["modules"]) == 6

    async def test_scanner_failure_handled_in_full_flow(self, client):
        """Un scanner qui crashe n'empêche pas les autres de compléter."""
        dns_resolver = _dns_mock()
        cert_info = _ssl_mock_context()
        rep_patches = _reputation_patches()

        with (
            patch("app.scanners.dns.dns.asyncresolver.Resolver", return_value=dns_resolver),
            # TLS crashe
            patch("app.scanners.tls._get_cert_info", new_callable=AsyncMock,
                  side_effect=Exception("TLS scanner crashed")),
            patch("app.scanners.testssl_runner.is_available", return_value=False),
            rep_patches["resolve_ips"],
            rep_patches["spamhaus"],
            rep_patches["env_key"],
            patch("app.scanners.subdomains._fetch_subdomains", new_callable=AsyncMock, return_value=set()),
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

        # TLS est en erreur — le scanner de base capture l'exception et retourne un finding critical
        tls = modules_by_name["tls"]
        assert tls["status"] == "completed"
        # Le scanner TLS gère l'exception avec un finding "Connexion TLS impossible"
        tls_findings = tls["findings"]
        assert len(tls_findings) >= 1
        assert any("TLS" in f["title"] or "impossible" in f["title"].lower() for f in tls_findings)

        # Les autres scanners ont complété normalement
        for name in ("dns", "headers", "reputation", "subdomains", "leaks"):
            assert modules_by_name[name]["status"] == "completed"
            assert modules_by_name[name]["score"] is not None

    async def test_delete_scan_removes_everything(self, client):
        """DELETE /api/scans/{id} supprime scan + modules + findings (cascade)."""
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

            # Confirmer que le scan existe
            resp = await client.get(f"/api/scans/{scan_id}")
            assert resp.status_code == 200
            assert len(resp.json()["modules"]) == 6

            # Supprimer
            resp = await client.delete(f"/api/scans/{scan_id}")
            assert resp.status_code == 204

            # Le scan n'existe plus
            resp = await client.get(f"/api/scans/{scan_id}")
            assert resp.status_code == 404

    async def test_finding_fields_survive_serialization(self, client):
        """
        Vérifie que les champs FindingData (severity, title, description,
        remediation) survivent au passage Scanner → DB → API JSON.
        """
        dns_resolver = _dns_mock()
        rep_patches = _reputation_patches()

        # Cert expiré pour forcer un finding avec remediation non-null
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

        # Trouver le finding "Certificat TLS expiré"
        tls_module = next(m for m in data["modules"] if m["name"] == "tls")
        expired_finding = next(
            (f for f in tls_module["findings"] if "expiré" in f["title"].lower()),
            None,
        )

        assert expired_finding is not None
        assert expired_finding["severity"] == "critical"
        assert expired_finding["title"] == "Certificat TLS expiré"
        assert "expiré" in expired_finding["description"]
        assert expired_finding["remediation"] is not None
        assert "renouveler" in expired_finding["remediation"].lower()

    async def test_weighted_score_calculation_end_to_end(self, client):
        """
        Vérifie que le score global est bien la moyenne pondérée des modules,
        calculée par l'orchestrateur et retournée par l'API.
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

        # Le grade correspond au score
        from app.scanners.orchestrator import score_to_grade
        assert data["grade"] == score_to_grade(data["score"])
