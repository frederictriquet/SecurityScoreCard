"""Tests pour app.scanners.leaks — LeaksScanner, HIBP API."""

import pytest
from unittest.mock import patch, AsyncMock

import httpx

from app.scanners.leaks import LeaksScanner, HIBP_URL
from app.scanners.base import FindingData


@pytest.fixture
def scanner():
    return LeaksScanner()


# ===================================================================
# Scanner metadata
# ===================================================================


class TestLeaksScannerMeta:
    def test_name(self, scanner):
        assert scanner.name == "leaks"

    def test_weight(self, scanner):
        assert scanner.weight == 0.15

    def test_hibp_url_template(self):
        assert "{domain}" in HIBP_URL


# ===================================================================
# Full scan — HIBP responses
# ===================================================================


class TestLeaksScan:
    async def test_no_breaches_404(self, scanner):
        import respx

        with respx.mock:
            respx.get(
                "https://haveibeenpwned.com/api/v3/breacheddomain/example.com"
            ).mock(return_value=httpx.Response(404))

            result = await scanner.scan("example.com")
        assert result.score == 100
        assert len(result.findings) == 0

    async def test_domain_not_supported_400(self, scanner):
        import respx

        with respx.mock:
            respx.get(
                "https://haveibeenpwned.com/api/v3/breacheddomain/example.com"
            ).mock(return_value=httpx.Response(400))

            result = await scanner.scan("example.com")
        assert len(result.findings) == 1
        assert result.findings[0].severity == "info"
        assert "non supporté" in result.findings[0].title.lower()

    async def test_unexpected_status_code(self, scanner):
        import respx

        with respx.mock:
            respx.get(
                "https://haveibeenpwned.com/api/v3/breacheddomain/example.com"
            ).mock(return_value=httpx.Response(503))

            result = await scanner.scan("example.com")
        assert len(result.findings) == 1
        assert result.findings[0].severity == "info"
        assert "503" in result.findings[0].title

    async def test_empty_breaches_dict(self, scanner):
        import respx

        with respx.mock:
            respx.get(
                "https://haveibeenpwned.com/api/v3/breacheddomain/example.com"
            ).mock(return_value=httpx.Response(200, json={}))

            result = await scanner.scan("example.com")
        assert result.score == 100
        assert len(result.findings) == 0

    async def test_1_breach_low_severity(self, scanner):
        import respx

        with respx.mock:
            respx.get(
                "https://haveibeenpwned.com/api/v3/breacheddomain/example.com"
            ).mock(return_value=httpx.Response(200, json={
                "BreachA": ["user1@example.com"],
            }))

            result = await scanner.scan("example.com")
        assert len(result.findings) == 1
        assert result.findings[0].severity == "low"
        assert "1 breach" in result.findings[0].title

    async def test_2_breaches_low_severity(self, scanner):
        import respx

        with respx.mock:
            respx.get(
                "https://haveibeenpwned.com/api/v3/breacheddomain/example.com"
            ).mock(return_value=httpx.Response(200, json={
                "BreachA": ["u1"],
                "BreachB": ["u2"],
            }))

            result = await scanner.scan("example.com")
        assert result.findings[0].severity == "low"  # 2 <= 2

    async def test_3_breaches_medium_severity(self, scanner):
        import respx

        breaches = {f"Breach{i}": [f"u{i}"] for i in range(3)}
        with respx.mock:
            respx.get(
                "https://haveibeenpwned.com/api/v3/breacheddomain/example.com"
            ).mock(return_value=httpx.Response(200, json=breaches))

            result = await scanner.scan("example.com")
        assert result.findings[0].severity == "medium"

    async def test_5_breaches_medium_severity(self, scanner):
        import respx

        breaches = {f"Breach{i}": [f"u{i}"] for i in range(5)}
        with respx.mock:
            respx.get(
                "https://haveibeenpwned.com/api/v3/breacheddomain/example.com"
            ).mock(return_value=httpx.Response(200, json=breaches))

            result = await scanner.scan("example.com")
        assert result.findings[0].severity == "medium"  # 5 is not > 5

    async def test_6_breaches_high_severity(self, scanner):
        import respx

        breaches = {f"Breach{i}": [f"u{i}"] for i in range(6)}
        with respx.mock:
            respx.get(
                "https://haveibeenpwned.com/api/v3/breacheddomain/example.com"
            ).mock(return_value=httpx.Response(200, json=breaches))

            result = await scanner.scan("example.com")
        assert result.findings[0].severity == "high"

    async def test_10_breaches_high_severity(self, scanner):
        import respx

        breaches = {f"Breach{i}": [f"u{i}"] for i in range(10)}
        with respx.mock:
            respx.get(
                "https://haveibeenpwned.com/api/v3/breacheddomain/example.com"
            ).mock(return_value=httpx.Response(200, json=breaches))

            result = await scanner.scan("example.com")
        assert result.findings[0].severity == "high"  # 10 is not > 10

    async def test_11_breaches_critical_severity(self, scanner):
        import respx

        breaches = {f"Breach{i}": [f"u{i}"] for i in range(11)}
        with respx.mock:
            respx.get(
                "https://haveibeenpwned.com/api/v3/breacheddomain/example.com"
            ).mock(return_value=httpx.Response(200, json=breaches))

            result = await scanner.scan("example.com")
        assert result.findings[0].severity == "critical"
        assert "11 breach" in result.findings[0].title

    async def test_breach_names_in_description(self, scanner):
        import respx

        with respx.mock:
            respx.get(
                "https://haveibeenpwned.com/api/v3/breacheddomain/example.com"
            ).mock(return_value=httpx.Response(200, json={
                "Adobe": ["u1"],
                "LinkedIn": ["u2"],
                "Dropbox": ["u3"],
            }))

            result = await scanner.scan("example.com")
        desc = result.findings[0].description
        # Au moins quelques noms de breach doivent apparaître
        assert any(name in desc for name in ["Adobe", "LinkedIn", "Dropbox"])

    async def test_more_than_5_breaches_shows_et_dautres(self, scanner):
        import respx

        breaches = {f"Breach{i}": [f"u{i}"] for i in range(7)}
        with respx.mock:
            respx.get(
                "https://haveibeenpwned.com/api/v3/breacheddomain/example.com"
            ).mock(return_value=httpx.Response(200, json=breaches))

            result = await scanner.scan("example.com")
        assert "et d'autres" in result.findings[0].description

    async def test_exactly_5_breaches_no_et_dautres(self, scanner):
        import respx

        breaches = {f"Breach{i}": [f"u{i}"] for i in range(5)}
        with respx.mock:
            respx.get(
                "https://haveibeenpwned.com/api/v3/breacheddomain/example.com"
            ).mock(return_value=httpx.Response(200, json=breaches))

            result = await scanner.scan("example.com")
        assert "et d'autres" not in result.findings[0].description

    async def test_connection_error(self, scanner):
        import respx

        with respx.mock:
            respx.get(
                "https://haveibeenpwned.com/api/v3/breacheddomain/example.com"
            ).mock(side_effect=httpx.ConnectError("timeout"))

            result = await scanner.scan("example.com")
        assert len(result.findings) == 1
        assert result.findings[0].severity == "info"
        assert "erreur de connexion" in result.findings[0].title.lower()

    async def test_score_deduction_for_breaches(self, scanner):
        import respx

        breaches = {f"Breach{i}": [f"u{i}"] for i in range(3)}
        with respx.mock:
            respx.get(
                "https://haveibeenpwned.com/api/v3/breacheddomain/example.com"
            ).mock(return_value=httpx.Response(200, json=breaches))

            result = await scanner.scan("example.com")
        # 3 breaches → medium → -10 → score = 90
        assert result.score == 90

    async def test_remediation_present(self, scanner):
        import respx

        with respx.mock:
            respx.get(
                "https://haveibeenpwned.com/api/v3/breacheddomain/example.com"
            ).mock(return_value=httpx.Response(200, json={
                "BreachA": ["u1"],
            }))

            result = await scanner.scan("example.com")
        assert result.findings[0].remediation is not None
        assert "multi-facteurs" in result.findings[0].remediation
