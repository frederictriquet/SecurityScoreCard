"""Tests for app.scanners.reputation — ReputationScanner, AbuseIPDB, Spamhaus."""

import pytest
from unittest.mock import patch, AsyncMock, MagicMock
import socket

import httpx
import dns.resolver
import dns.asyncresolver

from app.scanners.reputation import (
    ReputationScanner,
    _resolve_ips,
    _check_abuseipdb,
    _check_spamhaus_dns,
    _registrable_domain,
    _decode_dnsbl,
    _check_surbl_uribl,
    SURBL_BITS,
    URIBL_BITS,
)
from app.scanners.base import FindingData
from tests.conftest import FakeDnsAnswer


class FakeARecord:
    """Simulate a dns A record whose ``str()`` yields the IP address."""

    def __init__(self, ip: str):
        self._ip = ip

    def __str__(self) -> str:
        return self._ip


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
        assert len(findings) == 0  # score <= 5 → skip

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
        assert len(findings) == 1  # only the first IP has a high score

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
        assert "42 report" in findings[0].description


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
            # The query should be 34.216.184.93.zen.spamhaus.org
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
        with (
            patch("app.scanners.reputation._resolve_ips", return_value=[]),
            patch("app.scanners.reputation._check_surbl_uribl", new_callable=AsyncMock),
        ):
            result = await scanner.scan("nonexistent.example.com")
            assert len(result.findings) == 1
            assert result.findings[0].severity == "info"

    async def test_with_abuseipdb_key(self, scanner):
        with (
            patch("app.scanners.reputation._check_surbl_uribl", new_callable=AsyncMock),
            patch("app.scanners.reputation._resolve_ips", return_value=["1.2.3.4"]),
            patch("os.getenv", return_value="fake-key"),
            patch("app.scanners.reputation._check_abuseipdb", new_callable=AsyncMock) as mock_abuse,
        ):
            await scanner.scan("example.com")
            mock_abuse.assert_called_once()

    async def test_without_abuseipdb_key_falls_back_to_spamhaus(self, scanner):
        with (
            patch("app.scanners.reputation._check_surbl_uribl", new_callable=AsyncMock),
            patch("app.scanners.reputation._resolve_ips", return_value=["1.2.3.4"]),
            patch("os.getenv", return_value=""),
            patch("app.scanners.reputation._check_spamhaus_dns") as mock_spam,
        ):
            await scanner.scan("example.com")
            mock_spam.assert_called_once()

    async def test_surbl_uribl_called(self, scanner):
        with (
            patch("app.scanners.reputation._resolve_ips", return_value=["1.2.3.4"]),
            patch("os.getenv", return_value=""),
            patch("app.scanners.reputation._check_spamhaus_dns"),
            patch(
                "app.scanners.reputation._check_surbl_uribl", new_callable=AsyncMock
            ) as mock_surbl,
        ):
            await scanner.scan("example.com")
            mock_surbl.assert_called_once()

    async def test_surbl_uribl_runs_even_without_ips(self, scanner):
        with (
            patch("app.scanners.reputation._resolve_ips", return_value=[]),
            patch(
                "app.scanners.reputation._check_surbl_uribl", new_callable=AsyncMock
            ) as mock_surbl,
        ):
            await scanner.scan("nonexistent.example.com")
            mock_surbl.assert_called_once()


# ===================================================================
# _registrable_domain
# ===================================================================


class TestRegistrableDomain:
    def test_simple_domain_unchanged(self):
        assert _registrable_domain("example.com") == "example.com"

    def test_strips_subdomain(self):
        assert _registrable_domain("mail.foo.example.com") == "example.com"

    def test_multi_part_tld(self):
        assert _registrable_domain("example.co.uk") == "example.co.uk"

    def test_subdomain_with_multi_part_tld(self):
        assert _registrable_domain("mail.example.co.uk") == "example.co.uk"

    def test_case_insensitive_and_trailing_dot(self):
        assert _registrable_domain("WWW.Example.COM.") == "example.com"


# ===================================================================
# _decode_dnsbl
# ===================================================================


class TestDecodeDnsbl:
    def test_not_listed(self):
        listed, sublists, refused = _decode_dnsbl([], SURBL_BITS)
        assert (listed, sublists, refused) == (False, [], False)

    def test_listed_with_bitmask(self):
        # 24 = 8 (phishing) | 16 (malware)
        listed, sublists, refused = _decode_dnsbl(["127.0.0.24"], SURBL_BITS)
        assert listed is True
        assert sublists == ["malware", "phishing"]
        assert refused is False

    def test_listed_without_known_bit(self):
        # 127.0.0.2 does not match any SURBL bit -> generic listing
        listed, sublists, refused = _decode_dnsbl(["127.0.0.2"], SURBL_BITS)
        assert listed is True
        assert sublists == []
        assert refused is False

    def test_refused_code_not_a_listing(self):
        listed, sublists, refused = _decode_dnsbl(["127.0.0.1"], URIBL_BITS)
        assert listed is False
        assert sublists == []
        assert refused is True

    def test_non_loopback_response_ignored(self):
        listed, sublists, refused = _decode_dnsbl(["1.2.3.4"], SURBL_BITS)
        assert (listed, sublists, refused) == (False, [], False)


# ===================================================================
# _check_surbl_uribl
# ===================================================================


def _resolver_returning(mapping):
    """Build a resolve() side_effect from a {fqdn: outcome} mapping.

    Each outcome is either a FakeDnsAnswer, or an exception instance/class to
    raise (e.g. NXDOMAIN, timeout).
    """
    async def _resolve(fqdn, _rdtype):
        outcome = mapping[fqdn]
        if isinstance(outcome, BaseException) or (
            isinstance(outcome, type) and issubclass(outcome, BaseException)
        ):
            raise outcome
        return outcome

    return _resolve


class TestCheckSurblUribl:
    async def test_listed_on_surbl(self):
        findings = []
        mapping = {
            "example.com.multi.surbl.org": FakeDnsAnswer([FakeARecord("127.0.0.8")]),
            "example.com.multi.uribl.com": dns.resolver.NXDOMAIN,
        }
        resolver = AsyncMock(spec=dns.asyncresolver.Resolver)
        resolver.resolve = _resolver_returning(mapping)
        with patch("dns.asyncresolver.Resolver", return_value=resolver):
            await _check_surbl_uribl("example.com", findings)
        assert len(findings) == 1
        assert findings[0].severity == "medium"
        assert "SURBL" in findings[0].title
        assert "phishing" in findings[0].description
        assert "surbl.org" in findings[0].remediation

    async def test_listed_on_both(self):
        findings = []
        mapping = {
            "example.com.multi.surbl.org": FakeDnsAnswer([FakeARecord("127.0.0.16")]),
            "example.com.multi.uribl.com": FakeDnsAnswer([FakeARecord("127.0.0.2")]),
        }
        resolver = AsyncMock(spec=dns.asyncresolver.Resolver)
        resolver.resolve = _resolver_returning(mapping)
        with patch("dns.asyncresolver.Resolver", return_value=resolver):
            await _check_surbl_uribl("example.com", findings)
        assert len(findings) == 1
        assert "SURBL" in findings[0].title
        assert "URIBL" in findings[0].title

    async def test_clean_domain_no_finding(self):
        findings = []
        mapping = {
            "example.com.multi.surbl.org": dns.resolver.NXDOMAIN,
            "example.com.multi.uribl.com": dns.resolver.NXDOMAIN,
        }
        resolver = AsyncMock(spec=dns.asyncresolver.Resolver)
        resolver.resolve = _resolver_returning(mapping)
        with patch("dns.asyncresolver.Resolver", return_value=resolver):
            await _check_surbl_uribl("example.com", findings)
        assert len(findings) == 0

    async def test_uribl_refused_code_is_not_a_hit(self):
        findings = []
        mapping = {
            "example.com.multi.surbl.org": dns.resolver.NXDOMAIN,
            # 127.0.0.1 = query refused / rate-limited, must NOT be a listing
            "example.com.multi.uribl.com": FakeDnsAnswer([FakeARecord("127.0.0.1")]),
        }
        resolver = AsyncMock(spec=dns.asyncresolver.Resolver)
        resolver.resolve = _resolver_returning(mapping)
        with patch("dns.asyncresolver.Resolver", return_value=resolver):
            await _check_surbl_uribl("example.com", findings)
        assert len(findings) == 1
        assert findings[0].severity == "info"
        assert "undetermined" in findings[0].title.lower()
        assert "URIBL" in findings[0].description

    async def test_dns_error_does_not_crash(self):
        findings = []
        mapping = {
            "example.com.multi.surbl.org": dns.resolver.LifetimeTimeout,
            "example.com.multi.uribl.com": Exception("boom"),
        }
        resolver = AsyncMock(spec=dns.asyncresolver.Resolver)
        resolver.resolve = _resolver_returning(mapping)
        with patch("dns.asyncresolver.Resolver", return_value=resolver):
            await _check_surbl_uribl("example.com", findings)
        assert len(findings) == 0

    async def test_uses_registrable_domain(self):
        findings = []
        mapping = {
            "example.co.uk.multi.surbl.org": dns.resolver.NXDOMAIN,
            "example.co.uk.multi.uribl.com": dns.resolver.NXDOMAIN,
        }
        resolver = AsyncMock(spec=dns.asyncresolver.Resolver)
        resolver.resolve = _resolver_returning(mapping)
        with patch("dns.asyncresolver.Resolver", return_value=resolver):
            # subdomain should be reduced to the registrable domain
            await _check_surbl_uribl("mail.example.co.uk", findings)
        assert len(findings) == 0
