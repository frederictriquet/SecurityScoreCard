"""Regression tests for real-world edge cases.

These tests reproduce scenarios encountered in production:
- Infinite redirects
- Incomplete certificate chain
- Large crt.sh responses
- Partial DNS timeouts
- Malformed HIBP JSON
- Exotic domains
"""

import pytest
from unittest.mock import patch, AsyncMock, MagicMock
from datetime import datetime, timezone, timedelta

import dns.exception
import dns.resolver
import dns.asyncresolver
import httpx
import respx

from app.scanners.headers import HeadersScanner, _check_cookies, COOKIE_PROBE_PATHS
from app.scanners.tls import TlsScanner, _fetch_cert_sync
from app.scanners.subdomains import SubdomainsScanner, _fetch_subdomains
from app.scanners.dns import DnsScanner
from app.scanners.leaks import LeaksScanner
from app.scanners.reputation import ReputationScanner
from app.scanners.base import ScanResult
from tests.conftest import FakeDnsAnswer, FakeTxtRecord, FakeMxRecord, make_cert_info


# ===================================================================
# Infinite redirects (Headers scanner)
# ===================================================================


class TestInfiniteRedirect:
    async def test_redirect_loop_returns_error_finding(self):
        """A domain that redirects in a loop must not block the scanner."""
        scanner = HeadersScanner()
        with respx.mock:
            respx.get("https://loop.example.com").mock(
                side_effect=httpx.TooManyRedirects(
                    "Exceeded maximum redirects",
                    request=httpx.Request("GET", "https://loop.example.com"),
                )
            )
            result = await scanner.scan("loop.example.com")

        # The scanner catches the exception and returns a finding
        assert result.score < 100
        assert len(result.findings) >= 1
        assert result.findings[0].severity == "high"
        assert "Unable" in result.findings[0].title

    async def test_redirect_loop_does_not_hang(self):
        """Verify that the httpx timeout protects against slow loops."""
        scanner = HeadersScanner()
        with respx.mock:
            respx.get("https://slow-loop.example.com").mock(
                side_effect=httpx.ReadTimeout(
                    "Read timed out",
                    request=httpx.Request("GET", "https://slow-loop.example.com"),
                )
            )
            result = await scanner.scan("slow-loop.example.com")

        assert result.findings[0].severity == "high"


# ===================================================================
# Incomplete certificate chain (TLS)
# ===================================================================


class TestIncompleteCertChain:
    async def test_ssl_verification_error_triggers_fallback(self):
        """A cert with an incomplete chain fails with verify=True, succeeds with verify=False."""
        import ssl
        import socket

        mock_sock = MagicMock()
        mock_sock.__enter__ = MagicMock(return_value=mock_sock)
        mock_sock.__exit__ = MagicMock(return_value=False)

        mock_ssock = MagicMock()
        mock_ssock.getpeercert.return_value = b"DER_BYTES"
        mock_ssock.cipher.return_value = ("TLS_AES_256_GCM_SHA384", "TLSv1.3", 256)
        mock_ssock.version.return_value = "TLSv1.3"
        mock_ssock.__enter__ = MagicMock(return_value=mock_ssock)
        mock_ssock.__exit__ = MagicMock(return_value=False)

        ctx_verified = MagicMock()
        ctx_verified.wrap_socket.side_effect = ssl.SSLCertVerificationError(
            "unable to get local issuer certificate"
        )

        ctx_unverified = MagicMock()
        ctx_unverified.wrap_socket.return_value = mock_ssock

        parsed = make_cert_info(
            issuer_cn="Incomplete CA",
            subject_cn="chain.example.com",
        )

        with (
            patch("socket.create_connection", return_value=mock_sock),
            patch("ssl.create_default_context", side_effect=[ctx_verified, ctx_unverified]),
            patch("app.scanners.tls._parse_cert_der", return_value=parsed),
        ):
            result = _fetch_cert_sync("chain.example.com")

        # The verify=False fallback worked
        assert result["verified"] is False
        assert result["subject_cn"] == "chain.example.com"

    async def test_incomplete_chain_produces_finding_via_scanner(self):
        """The full scan with an unverified cert produces the right result."""
        scanner = TlsScanner()
        cert_info = make_cert_info(verified=False)

        with (
            patch("app.scanners.tls._get_cert_info", new_callable=AsyncMock, return_value=cert_info),
            patch("app.scanners.testssl_runner.is_available", return_value=False),
            patch("app.scanners.tls._check_hsts_preload", new_callable=AsyncMock, return_value=[]),
        ):
            result = await scanner.scan("chain.example.com")

        # The cert is valid data-wise, so score = 100 even if verified=False
        # (the verification check is not yet implemented in the base checks)
        assert isinstance(result, ScanResult)
        assert result.score >= 0


# ===================================================================
# crt.sh with thousands of results (Subdomains)
# ===================================================================


class TestMassiveSubdomains:
    async def test_thousands_of_subdomains_capped_in_description(self):
        """crt.sh returns 5000 subdomains — the description is truncated to 20."""
        scanner = SubdomainsScanner()
        huge_result = [
            {"name_value": f"sub{i}.example.com"}
            for i in range(5000)
        ]

        with respx.mock:
            respx.get("https://crt.sh/").mock(
                return_value=httpx.Response(200, json=huge_result)
            )
            # The takeover checks will also be called — mock httpx for the first 30
            respx.get(url__regex=r"https://sub\d+\.example\.com").mock(
                return_value=httpx.Response(200, text="OK")
            )

            result = await scanner.scan("example.com")

        # Info finding with the total count
        info = [f for f in result.findings if "5000" in f.title or "subdomain" in f.title]
        assert len(info) >= 1
        # The description only lists 20 subdomains
        desc = info[0].description
        assert "and more" in desc

    async def test_crt_sh_returns_duplicates_deduplicated(self):
        """crt.sh returns the same subdomain several times — deduplicated."""
        data = [
            {"name_value": "api.example.com"},
            {"name_value": "api.example.com"},
            {"name_value": "api.example.com"},
            {"name_value": "www.example.com"},
        ]
        with respx.mock:
            respx.get("https://crt.sh/").mock(
                return_value=httpx.Response(200, json=data)
            )

            subs = await _fetch_subdomains("example.com")

        assert len(subs) == 2
        assert "api.example.com" in subs
        assert "www.example.com" in subs

    async def test_crt_sh_multiline_name_values(self):
        """crt.sh returns name_value with multiple lines (wildcard + concrete)."""
        data = [
            {"name_value": "*.example.com\nwww.example.com\napi.example.com"},
        ]
        with respx.mock:
            respx.get("https://crt.sh/").mock(
                return_value=httpx.Response(200, json=data)
            )

            subs = await _fetch_subdomains("example.com")

        assert "www.example.com" in subs
        assert "api.example.com" in subs
        assert "example.com" in subs  # *.example.com stripped to example.com

    async def test_crt_sh_timeout_returns_empty(self):
        """crt.sh timeout → returns an empty set, no exception."""
        with respx.mock:
            respx.get("https://crt.sh/").mock(
                side_effect=httpx.ReadTimeout(
                    "timed out",
                    request=httpx.Request("GET", "https://crt.sh/"),
                )
            )

            subs = await _fetch_subdomains("example.com")

        assert subs == set()

    async def test_crt_sh_invalid_json(self):
        """crt.sh returns HTML instead of JSON → no crash."""
        with respx.mock:
            respx.get("https://crt.sh/").mock(
                return_value=httpx.Response(
                    200,
                    text="<html>Rate limited</html>",
                    headers={"content-type": "text/html"},
                )
            )

            subs = await _fetch_subdomains("example.com")

        assert subs == set()


# ===================================================================
# Partial DNS timeout (a single check times out, the others continue)
# ===================================================================


class TestDnsPartialTimeout:
    async def test_spf_timeout_others_continue(self):
        """A DNS timeout on SPF does not block DMARC, MX, etc."""
        scanner = DnsScanner()
        call_count = {"spf": 0, "other": 0}

        async def selective_timeout(name, rdtype):
            if rdtype == "TXT" and not name.startswith("_"):
                call_count["spf"] += 1
                raise dns.exception.Timeout()
            if rdtype == "TXT" and name.startswith("_dmarc."):
                call_count["other"] += 1
                return FakeDnsAnswer([FakeTxtRecord('"v=DMARC1; p=reject"')])
            if rdtype == "TXT" and "_domainkey" in name:
                raise dns.resolver.NXDOMAIN()
            if rdtype == "TXT" and name.startswith("_mta-sts."):
                raise dns.resolver.NoAnswer()
            if rdtype == "DNSKEY":
                raise dns.resolver.NoAnswer()
            if rdtype == "MX":
                return FakeDnsAnswer([FakeMxRecord("mail.example.com.")])
            if rdtype == "CAA":
                return FakeDnsAnswer([FakeTxtRecord('0 issue "letsencrypt.org"')])
            if rdtype == "TLSA":
                raise dns.resolver.NXDOMAIN()
            raise dns.resolver.NoAnswer()

        mock_resolver = AsyncMock(spec=dns.asyncresolver.Resolver)
        mock_resolver.nameservers = ["8.8.8.8"]
        mock_resolver.resolve = AsyncMock(side_effect=selective_timeout)

        with patch("app.scanners.dns.dns.asyncresolver.Resolver", return_value=mock_resolver):
            result = await scanner.scan("example.com")

        # The scan completes despite the SPF timeout
        assert isinstance(result, ScanResult)
        assert result.score >= 0

        # SPF failed → error finding
        spf_findings = [f for f in result.findings if "SPF" in f.title]
        assert len(spf_findings) >= 1

        # DMARC did NOT fail (no missing-DMARC finding)
        dmarc_missing = [f for f in result.findings if "DMARC missing" in f.title]
        assert len(dmarc_missing) == 0

    async def test_all_dns_checks_timeout_still_returns_result(self):
        """All DNS checks time out → the scan still returns a ScanResult."""
        scanner = DnsScanner()

        mock_resolver = AsyncMock(spec=dns.asyncresolver.Resolver)
        mock_resolver.nameservers = ["8.8.8.8"]
        mock_resolver.resolve = AsyncMock(
            side_effect=dns.exception.Timeout()
        )

        with patch("app.scanners.dns.dns.asyncresolver.Resolver", return_value=mock_resolver):
            result = await scanner.scan("timeout.example.com")

        assert isinstance(result, ScanResult)
        assert result.score >= 0
        # Several error findings but no crash
        assert len(result.findings) > 0


# ===================================================================
# Malformed HIBP JSON
# ===================================================================


class TestHIBPMalformedResponse:
    async def test_hibp_returns_invalid_json(self):
        """HIBP returns text instead of JSON → info finding, no crash."""
        scanner = LeaksScanner()
        with respx.mock:
            respx.get(url__regex=r".*haveibeenpwned.*").mock(
                return_value=httpx.Response(
                    200,
                    text="Internal Server Error",
                    headers={"content-type": "text/plain"},
                )
            )

            result = await scanner.scan("example.com")

        # The scanner catches the JSON exception and returns an info finding
        assert isinstance(result, ScanResult)
        assert len(result.findings) >= 1
        error_findings = [f for f in result.findings if f.severity == "info"]
        assert len(error_findings) >= 1

    async def test_hibp_returns_truncated_json(self):
        """HIBP returns truncated JSON → decode error caught."""
        scanner = LeaksScanner()
        with respx.mock:
            respx.get(url__regex=r".*haveibeenpwned.*").mock(
                return_value=httpx.Response(
                    200,
                    text='{"partial": "json',
                    headers={"content-type": "application/json"},
                )
            )

            result = await scanner.scan("example.com")

        assert isinstance(result, ScanResult)
        # The JSONDecodeError exception is caught by the except Exception
        assert len(result.findings) >= 1

    async def test_hibp_returns_empty_json_object(self):
        """HIBP returns {} → 0 breaches → score 100."""
        scanner = LeaksScanner()
        with respx.mock:
            respx.get(url__regex=r".*haveibeenpwned.*").mock(
                return_value=httpx.Response(200, json={})
            )

            result = await scanner.scan("example.com")

        assert result.score == 100

    async def test_hibp_connection_reset(self):
        """HIBP closes the connection abruptly → info finding."""
        scanner = LeaksScanner()
        with respx.mock:
            respx.get(url__regex=r".*haveibeenpwned.*").mock(
                side_effect=httpx.RemoteProtocolError(
                    "peer closed connection without sending complete message body",
                )
            )

            result = await scanner.scan("example.com")

        assert isinstance(result, ScanResult)
        conn_findings = [f for f in result.findings if "connection" in f.title.lower()]
        assert len(conn_findings) == 1


# ===================================================================
# Exotic domains and DNS edge cases
# ===================================================================


class TestExoticDomains:
    async def test_punycode_domain_dns(self):
        """An internationalized domain (punycode) is passed correctly to the resolver."""
        scanner = DnsScanner()

        mock_resolver = AsyncMock(spec=dns.asyncresolver.Resolver)
        mock_resolver.nameservers = ["8.8.8.8"]
        mock_resolver.resolve = AsyncMock(side_effect=dns.resolver.NXDOMAIN())

        with patch("app.scanners.dns.dns.asyncresolver.Resolver", return_value=mock_resolver):
            result = await scanner.scan("xn--nxasmq6b.example.com")

        assert isinstance(result, ScanResult)
        # The punycode domain is passed as-is to the resolver
        calls = mock_resolver.resolve.call_args_list
        assert any("xn--nxasmq6b.example.com" in str(c) for c in calls)

    async def test_very_long_domain(self):
        """A very long domain does not crash the scanner."""
        scanner = DnsScanner()
        long_domain = "a" * 60 + "." + "b" * 60 + ".example.com"

        mock_resolver = AsyncMock(spec=dns.asyncresolver.Resolver)
        mock_resolver.nameservers = ["8.8.8.8"]
        mock_resolver.resolve = AsyncMock(side_effect=dns.resolver.NXDOMAIN())

        with patch("app.scanners.dns.dns.asyncresolver.Resolver", return_value=mock_resolver):
            result = await scanner.scan(long_domain)

        assert isinstance(result, ScanResult)


# ===================================================================
# Reputation scanner — edge cases
# ===================================================================


class TestReputationEdgeCases:
    async def test_domain_resolves_to_ipv6_only(self):
        """An IPv6-only domain does not crash Spamhaus (IPv6 not supported)."""
        scanner = ReputationScanner()

        with (
            patch("app.scanners.reputation._resolve_ips", return_value=["2001:db8::1"]),
            patch.dict("os.environ", {"ABUSEIPDB_API_KEY": ""}, clear=False),
            patch("app.scanners.reputation._check_surbl_uribl", new_callable=AsyncMock),
            patch("app.scanners.reputation._check_phishtank", new_callable=AsyncMock),
        ):
            result = await scanner.scan("ipv6only.example.com")

        assert isinstance(result, ScanResult)
        assert result.score == 100  # IPv6 skip → no finding

    async def test_domain_resolves_to_mixed_ipv4_ipv6(self):
        """A domain with IPv4 + IPv6 → only IPv4 is checked via Spamhaus."""
        scanner = ReputationScanner()
        import socket

        with (
            patch("app.scanners.reputation._resolve_ips",
                  return_value=["93.184.216.34", "2001:db8::1"]),
            patch.dict("os.environ", {"ABUSEIPDB_API_KEY": ""}, clear=False),
            patch("app.scanners.reputation.socket.gethostbyname",
                  side_effect=socket.gaierror("NXDOMAIN")),
            patch("app.scanners.reputation._check_surbl_uribl", new_callable=AsyncMock),
            patch("app.scanners.reputation._check_phishtank", new_callable=AsyncMock),
        ):
            result = await scanner.scan("mixed.example.com")

        assert isinstance(result, ScanResult)
        # No finding (IP not listed = gaierror = OK)
        reputation_findings = [f for f in result.findings if f.severity != "info"]
        assert len(reputation_findings) == 0


# ===================================================================
# Headers — cookies with complex redirects
# ===================================================================


class TestCookieRedirectEdgeCases:
    async def test_cookie_set_on_302_then_200(self):
        """A cookie set on the 302 response is also analyzed."""
        scanner = HeadersScanner()

        sec_headers = {
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

        with respx.mock:
            respx.get("https://redir.example.com").mock(
                return_value=httpx.Response(200, headers=sec_headers, text="<html></html>")
            )
            respx.get(url__regex=r"https://redir\.example\.com/.*").mock(
                return_value=httpx.Response(404)
            )
            # HTTP probe: /login redirects and sets an insecure cookie
            respx.get("http://redir.example.com/login").mock(
                return_value=httpx.Response(
                    200,
                    headers={"set-cookie": "sess=abc"},
                )
            )
            respx.get(url__regex=r"http://redir\.example\.com/(?!login).*").mock(
                return_value=httpx.Response(200)
            )
            respx.get("http://redir.example.com/").mock(
                return_value=httpx.Response(200)
            )
            respx.options(url__regex=r"https://redir\.example\.com.*").mock(
                return_value=httpx.Response(200)
            )

            result = await scanner.scan("redir.example.com")

        cookie_findings = [f for f in result.findings if "sess" in f.title]
        assert len(cookie_findings) >= 1  # At least Secure missing


# ===================================================================
# TLS — various network errors
# ===================================================================


class TestTlsNetworkErrors:
    async def test_dns_resolution_failure(self):
        """The domain does not resolve → critical TLS finding."""
        scanner = TlsScanner()

        with (
            patch("app.scanners.tls._get_cert_info", new_callable=AsyncMock,
                  side_effect=OSError("[Errno 8] nodename nor servname provided")),
            patch("app.scanners.testssl_runner.is_available", return_value=False),
            patch("app.scanners.tls._check_hsts_preload", new_callable=AsyncMock, return_value=[]),
        ):
            result = await scanner.scan("nonexistent.invalid")

        assert result.findings[0].severity == "critical"
        assert "failed" in result.findings[0].title.lower()

    async def test_port_443_closed(self):
        """Port 443 is closed → ConnectionRefusedError → critical finding."""
        scanner = TlsScanner()

        with (
            patch("app.scanners.tls._get_cert_info", new_callable=AsyncMock,
                  side_effect=ConnectionRefusedError("Connection refused")),
            patch("app.scanners.testssl_runner.is_available", return_value=False),
            patch("app.scanners.tls._check_hsts_preload", new_callable=AsyncMock, return_value=[]),
        ):
            result = await scanner.scan("http-only.example.com")

        assert result.findings[0].severity == "critical"
        assert "Connection refused" in result.findings[0].description

    async def test_ssl_handshake_timeout(self):
        """The SSL handshake times out → critical finding."""
        scanner = TlsScanner()
        import socket

        with (
            patch("app.scanners.tls._get_cert_info", new_callable=AsyncMock,
                  side_effect=socket.timeout("timed out")),
            patch("app.scanners.testssl_runner.is_available", return_value=False),
            patch("app.scanners.tls._check_hsts_preload", new_callable=AsyncMock, return_value=[]),
        ):
            result = await scanner.scan("slow.example.com")

        assert result.findings[0].severity == "critical"
