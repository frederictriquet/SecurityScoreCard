"""Tests for app.scanners.subdomains — SubdomainsScanner, crt.sh, takeover."""

import pytest
from unittest.mock import patch, AsyncMock, MagicMock

import httpx

from app.scanners.subdomains import (
    SubdomainsScanner,
    _fetch_subdomains,
    _check_takeover,
    TAKEOVER_SIGNATURES,
)
from app.scanners.base import FindingData


@pytest.fixture
def scanner():
    return SubdomainsScanner()


# ===================================================================
# Scanner metadata
# ===================================================================


class TestSubdomainsScannerMeta:
    def test_name(self, scanner):
        assert scanner.name == "subdomains"

    def test_weight(self, scanner):
        assert scanner.weight == 0.10


# ===================================================================
# TAKEOVER_SIGNATURES config
# ===================================================================


class TestTakeoverSignatures:
    def test_known_services_present(self):
        assert "github.io" in TAKEOVER_SIGNATURES
        assert "herokuapp.com" in TAKEOVER_SIGNATURES
        assert "azurewebsites.net" in TAKEOVER_SIGNATURES
        assert "netlify.app" in TAKEOVER_SIGNATURES

    def test_all_are_strings(self):
        for sig in TAKEOVER_SIGNATURES:
            assert isinstance(sig, str)
            assert len(sig) > 0


# ===================================================================
# _fetch_subdomains
# ===================================================================


class TestFetchSubdomains:
    async def test_parses_crt_sh_response(self):
        import respx

        with respx.mock:
            respx.get("https://crt.sh/").mock(
                return_value=httpx.Response(200, json=[
                    {"name_value": "www.example.com"},
                    {"name_value": "mail.example.com"},
                    {"name_value": "*.example.com"},
                ])
            )
            result = await _fetch_subdomains("example.com")
        assert "www.example.com" in result
        assert "mail.example.com" in result
        assert "example.com" in result  # *.example.com → example.com after strip

    async def test_filters_unrelated_domains(self):
        import respx

        with respx.mock:
            respx.get("https://crt.sh/").mock(
                return_value=httpx.Response(200, json=[
                    {"name_value": "www.example.com"},
                    {"name_value": "evil.other.com"},
                ])
            )
            result = await _fetch_subdomains("example.com")
        assert "www.example.com" in result
        assert "evil.other.com" not in result

    async def test_handles_multiline_name_value(self):
        import respx

        with respx.mock:
            respx.get("https://crt.sh/").mock(
                return_value=httpx.Response(200, json=[
                    {"name_value": "www.example.com\napi.example.com"},
                ])
            )
            result = await _fetch_subdomains("example.com")
        assert "www.example.com" in result
        assert "api.example.com" in result

    async def test_deduplicates_results(self):
        import respx

        with respx.mock:
            respx.get("https://crt.sh/").mock(
                return_value=httpx.Response(200, json=[
                    {"name_value": "www.example.com"},
                    {"name_value": "www.example.com"},
                    {"name_value": "www.example.com"},
                ])
            )
            result = await _fetch_subdomains("example.com")
        assert len([s for s in result if s == "www.example.com"]) == 1

    async def test_includes_bare_domain(self):
        import respx

        with respx.mock:
            respx.get("https://crt.sh/").mock(
                return_value=httpx.Response(200, json=[
                    {"name_value": "example.com"},
                ])
            )
            result = await _fetch_subdomains("example.com")
        assert "example.com" in result

    async def test_empty_response(self):
        import respx

        with respx.mock:
            respx.get("https://crt.sh/").mock(
                return_value=httpx.Response(200, json=[])
            )
            result = await _fetch_subdomains("example.com")
        assert result == set()

    async def test_connection_error_returns_empty(self):
        import respx

        with respx.mock:
            respx.get("https://crt.sh/").mock(
                side_effect=httpx.ConnectError("timeout")
            )
            result = await _fetch_subdomains("example.com")
        assert result == set()

    async def test_invalid_json_returns_empty(self):
        import respx

        with respx.mock:
            respx.get("https://crt.sh/").mock(
                return_value=httpx.Response(200, text="not json")
            )
            result = await _fetch_subdomains("example.com")
        assert result == set()


# ===================================================================
# _check_takeover
# ===================================================================


class TestCheckTakeover:
    async def test_takeover_detected(self):
        """A subdomain redirecting to a third-party service with a 404 → a single finding."""
        findings = []
        with patch("httpx.AsyncClient") as MockClient:
            mock_client = AsyncMock()
            MockClient.return_value.__aenter__ = AsyncMock(return_value=mock_client)
            MockClient.return_value.__aexit__ = AsyncMock(return_value=False)

            mock_resp = MagicMock()
            mock_resp.status_code = 404
            mock_resp.url = "https://dangling.github.io"
            mock_client.get = AsyncMock(return_value=mock_resp)

            await _check_takeover({"dangling.example.com"}, findings)

        assert len(findings) == 1
        assert findings[0].severity == "high"
        assert "takeover" in findings[0].title.lower()
        assert "github.io" in findings[0].description

    async def test_no_takeover_200_response(self):
        findings = []
        with patch("httpx.AsyncClient") as MockClient:
            mock_client = AsyncMock()
            MockClient.return_value.__aenter__ = AsyncMock(return_value=mock_client)
            MockClient.return_value.__aexit__ = AsyncMock(return_value=False)

            mock_resp = MagicMock()
            mock_resp.status_code = 200
            mock_resp.url = "https://www.example.com"
            mock_client.get = AsyncMock(return_value=mock_resp)

            await _check_takeover({"www.example.com"}, findings)
        assert len(findings) == 0

    async def test_404_without_takeover_signature(self):
        """A 404 whose URL contains no service signature → no finding."""
        findings = []
        with patch("httpx.AsyncClient") as MockClient:
            mock_client = AsyncMock()
            MockClient.return_value.__aenter__ = AsyncMock(return_value=mock_client)
            MockClient.return_value.__aexit__ = AsyncMock(return_value=False)

            mock_resp = MagicMock()
            mock_resp.status_code = 404
            mock_resp.url = "https://sub.example.com"  # no known signature
            mock_client.get = AsyncMock(return_value=mock_resp)

            await _check_takeover({"sub.example.com"}, findings)
        assert len(findings) == 0

    async def test_connection_error_silent(self):
        findings = []
        with patch("httpx.AsyncClient") as MockClient:
            mock_client = AsyncMock()
            MockClient.return_value.__aenter__ = AsyncMock(return_value=mock_client)
            MockClient.return_value.__aexit__ = AsyncMock(return_value=False)

            mock_client.get = AsyncMock(side_effect=httpx.ConnectError("timeout"))

            await _check_takeover({"sub.example.com"}, findings)
        assert len(findings) == 0

    async def test_limits_to_30_subdomains(self):
        """The code limits to 30 subdomains × len(TAKEOVER_SIGNATURES) requests."""
        findings = []
        subs = {f"sub{i}.example.com" for i in range(50)}

        with patch("httpx.AsyncClient") as MockClient:
            mock_client = AsyncMock()
            MockClient.return_value.__aenter__ = AsyncMock(return_value=mock_client)
            MockClient.return_value.__aexit__ = AsyncMock(return_value=False)

            mock_resp = MagicMock()
            mock_resp.status_code = 200
            mock_resp.url = "https://sub.example.com"
            mock_client.get = AsyncMock(return_value=mock_resp)

            await _check_takeover(subs, findings)
            # 50 subdomains but limited to 30, 1 request per subdomain
            assert mock_client.get.call_count == 30


# ===================================================================
# Full scan
# ===================================================================


class TestSubdomainsFullScan:
    async def test_no_subdomains_found(self, scanner):
        with patch("app.scanners.subdomains._fetch_subdomains", new_callable=AsyncMock) as mock:
            mock.return_value = set()
            result = await scanner.scan("example.com")
            assert len(result.findings) == 1
            assert result.findings[0].severity == "info"
            assert "No subdomain" in result.findings[0].title

    async def test_subdomains_found_listed(self, scanner):
        with (
            patch("app.scanners.subdomains._fetch_subdomains", new_callable=AsyncMock) as mock_fetch,
            patch("app.scanners.subdomains._check_takeover", new_callable=AsyncMock),
        ):
            mock_fetch.return_value = {"www.example.com", "api.example.com"}
            result = await scanner.scan("example.com")
            info_findings = [f for f in result.findings if f.severity == "info"]
            assert len(info_findings) >= 1
            assert "2 subdomain" in info_findings[0].title

    async def test_more_than_20_subdomains_truncated(self, scanner):
        with (
            patch("app.scanners.subdomains._fetch_subdomains", new_callable=AsyncMock) as mock_fetch,
            patch("app.scanners.subdomains._check_takeover", new_callable=AsyncMock),
        ):
            subs = {f"sub{i}.example.com" for i in range(25)}
            mock_fetch.return_value = subs
            result = await scanner.scan("example.com")
            info_findings = [f for f in result.findings if f.severity == "info"]
            assert "and more..." in info_findings[0].description
