"""Tests pour app.scanners.reputation — ReputationScanner, AbuseIPDB, Spamhaus."""

import pytest
from unittest.mock import patch, AsyncMock, MagicMock
import socket

import httpx

from app.scanners.reputation import (
    ReputationScanner,
    _resolve_ips,
    _check_abuseipdb,
    _check_spamhaus_dns,
)
from app.scanners.base import FindingData


@pytest.fixture
def scanner():
    return ReputationScanner()


# ===================================================================
# Scanner metadata
# ===================================================================


class TestReputationScannerMeta:
    def test_name(self, scanner):
        assert scanner.name == "reputation"

    def test_weight(self, scanner):
        assert scanner.weight == 0.15


# ===================================================================
# _resolve_ips
# ===================================================================


class TestResolveIps:
    def test_resolves_ipv4(self):
        with patch("socket.getaddrinfo") as mock:
            mock.return_value = [
                (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 0)),
            ]
            ips = _resolve_ips("example.com")
            assert ips == ["93.184.216.34"]

    def test_resolves_multiple_ips(self):
        with patch("socket.getaddrinfo") as mock:
            mock.return_value = [
                (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("1.2.3.4", 0)),
                (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("5.6.7.8", 0)),
            ]
            ips = _resolve_ips("example.com")
            assert len(ips) == 2

    def test_resolves_ipv6(self):
        with patch("socket.getaddrinfo") as mock:
            mock.return_value = [
                (socket.AF_INET6, socket.SOCK_STREAM, 6, "", ("2606:2800:220:1:248:1893:25c8:1946", 0, 0, 0)),
            ]
            ips = _resolve_ips("example.com")
            assert ips == ["2606:2800:220:1:248:1893:25c8:1946"]

    def test_resolve_failure_returns_empty(self):
        with patch("socket.getaddrinfo", side_effect=socket.gaierror("failed")):
            ips = _resolve_ips("nonexistent.example.com")
            assert ips == []


# ===================================================================
# _check_abuseipdb
# ===================================================================


class TestCheckAbuseIPDB:
    async def test_clean_ip_no_finding(self):
        import respx

        findings = []
        with respx.mock:
            respx.get("https://api.abuseipdb.com/api/v2/check").mock(
                return_value=httpx.Response(200, json={
                    "data": {"abuseConfidenceScore": 0, "totalReports": 0}
                })
            )
            await _check_abuseipdb(["1.2.3.4"], "fake-key", findings)
        assert len(findings) == 0

    async def test_low_score_5_to_20(self):
        import respx

        findings = []
        with respx.mock:
            respx.get("https://api.abuseipdb.com/api/v2/check").mock(
                return_value=httpx.Response(200, json={
                    "data": {"abuseConfidenceScore": 10, "totalReports": 3}
                })
            )
            await _check_abuseipdb(["1.2.3.4"], "fake-key", findings)
        assert len(findings) == 1
        assert findings[0].severity == "low"

    async def test_medium_score_21_to_50(self):
        import respx

        findings = []
        with respx.mock:
            respx.get("https://api.abuseipdb.com/api/v2/check").mock(
                return_value=httpx.Response(200, json={
                    "data": {"abuseConfidenceScore": 30, "totalReports": 10}
                })
            )
            await _check_abuseipdb(["1.2.3.4"], "fake-key", findings)
        assert len(findings) == 1
        assert findings[0].severity == "medium"

    async def test_high_score_51_to_80(self):
        import respx

        findings = []
        with respx.mock:
            respx.get("https://api.abuseipdb.com/api/v2/check").mock(
                return_value=httpx.Response(200, json={
                    "data": {"abuseConfidenceScore": 60, "totalReports": 50}
                })
            )
            await _check_abuseipdb(["1.2.3.4"], "fake-key", findings)
        assert len(findings) == 1
        assert findings[0].severity == "high"

    async def test_critical_score_above_80(self):
        import respx

        findings = []
        with respx.mock:
            respx.get("https://api.abuseipdb.com/api/v2/check").mock(
                return_value=httpx.Response(200, json={
                    "data": {"abuseConfidenceScore": 95, "totalReports": 200}
                })
            )
            await _check_abuseipdb(["1.2.3.4"], "fake-key", findings)
        assert len(findings) == 1
        assert findings[0].severity == "critical"
        assert "95/100" in findings[0].title

    async def test_score_exactly_5_no_finding(self):
        import respx

        findings = []
        with respx.mock:
            respx.get("https://api.abuseipdb.com/api/v2/check").mock(
                return_value=httpx.Response(200, json={
                    "data": {"abuseConfidenceScore": 5, "totalReports": 1}
                })
            )
            await _check_abuseipdb(["1.2.3.4"], "fake-key", findings)
        assert len(findings) == 0  # score <= 5 → continue

    async def test_multiple_ips(self):
        import respx

        findings = []
        with respx.mock:
            route = respx.get("https://api.abuseipdb.com/api/v2/check")
            route.side_effect = [
                httpx.Response(200, json={
                    "data": {"abuseConfidenceScore": 90, "totalReports": 100}
                }),
                httpx.Response(200, json={
                    "data": {"abuseConfidenceScore": 0, "totalReports": 0}
                }),
            ]
            await _check_abuseipdb(["1.2.3.4", "5.6.7.8"], "fake-key", findings)
        assert len(findings) == 1  # seule la première IP a un score élevé

    async def test_api_error_continues_silently(self):
        import respx

        findings = []
        with respx.mock:
            respx.get("https://api.abuseipdb.com/api/v2/check").mock(
                side_effect=httpx.ConnectError("timeout")
            )
            await _check_abuseipdb(["1.2.3.4"], "fake-key", findings)
        assert len(findings) == 0

    async def test_total_reports_in_description(self):
        import respx

        findings = []
        with respx.mock:
            respx.get("https://api.abuseipdb.com/api/v2/check").mock(
                return_value=httpx.Response(200, json={
                    "data": {"abuseConfidenceScore": 50, "totalReports": 42}
                })
            )
            await _check_abuseipdb(["1.2.3.4"], "fake-key", findings)
        # score 50 > 20 → medium
        assert "42 signalement" in findings[0].description


# ===================================================================
# _check_spamhaus_dns
# ===================================================================


class TestCheckSpamhausDns:
    def test_ip_listed(self):
        findings = []
        with patch("socket.gethostbyname", return_value="127.0.0.2"):
            _check_spamhaus_dns(["1.2.3.4"], findings)
        assert len(findings) == 1
        assert findings[0].severity == "high"
        assert "Spamhaus" in findings[0].title
        assert "1.2.3.4" in findings[0].title

    def test_ip_not_listed(self):
        findings = []
        with patch("socket.gethostbyname", side_effect=socket.gaierror("NXDOMAIN")):
            _check_spamhaus_dns(["1.2.3.4"], findings)
        assert len(findings) == 0

    def test_reversed_ip_format(self):
        findings = []
        with patch("socket.gethostbyname") as mock:
            mock.side_effect = socket.gaierror("NXDOMAIN")
            _check_spamhaus_dns(["93.184.216.34"], findings)
            # Le query devrait être 34.216.184.93.zen.spamhaus.org
            mock.assert_called_with("34.216.184.93.zen.spamhaus.org")

    def test_ipv6_skipped(self):
        findings = []
        with patch("socket.gethostbyname") as mock:
            _check_spamhaus_dns(["2001:db8::1"], findings)
            mock.assert_not_called()
        assert len(findings) == 0

    def test_multiple_ips_mixed(self):
        findings = []

        def side_effect(query):
            if "4.3.2.1" in query:
                return "127.0.0.2"
            raise socket.gaierror("NXDOMAIN")

        with patch("socket.gethostbyname", side_effect=side_effect):
            _check_spamhaus_dns(["1.2.3.4", "5.6.7.8"], findings)
        assert len(findings) == 1
        assert "1.2.3.4" in findings[0].title


# ===================================================================
# Full scan
# ===================================================================


class TestReputationFullScan:
    async def test_no_ips_resolved(self, scanner):
        with patch("app.scanners.reputation._resolve_ips", return_value=[]):
            result = await scanner.scan("nonexistent.example.com")
            assert len(result.findings) == 1
            assert result.findings[0].severity == "info"

    async def test_with_abuseipdb_key(self, scanner):
        with (
            patch("app.scanners.reputation._resolve_ips", return_value=["1.2.3.4"]),
            patch("os.getenv", return_value="fake-key"),
            patch("app.scanners.reputation._check_abuseipdb", new_callable=AsyncMock) as mock_abuse,
        ):
            await scanner.scan("example.com")
            mock_abuse.assert_called_once()

    async def test_without_abuseipdb_key_falls_back_to_spamhaus(self, scanner):
        with (
            patch("app.scanners.reputation._resolve_ips", return_value=["1.2.3.4"]),
            patch("os.getenv", return_value=""),
            patch("app.scanners.reputation._check_spamhaus_dns") as mock_spam,
        ):
            await scanner.scan("example.com")
            mock_spam.assert_called_once()
