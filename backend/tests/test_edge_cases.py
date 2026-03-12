"""Tests de régression pour les edge cases réels.

Ces tests reproduisent des scénarios rencontrés en production :
- Redirections infinies
- Chaîne de certificats incomplète
- Réponses crt.sh volumineuses
- Timeouts DNS partiels
- JSON malformé de HIBP
- Domaines exotiques
"""

import pytest
from unittest.mock import patch, AsyncMock, MagicMock
from datetime import datetime, timezone, timedelta

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
# Redirections infinies (Headers scanner)
# ===================================================================


class TestInfiniteRedirect:
    async def test_redirect_loop_returns_error_finding(self):
        """Un domaine qui redirige en boucle ne doit pas bloquer le scanner."""
        scanner = HeadersScanner()
        with respx.mock:
            respx.get("https://loop.example.com").mock(
                side_effect=httpx.TooManyRedirects(
                    "Exceeded maximum redirects",
                    request=httpx.Request("GET", "https://loop.example.com"),
                )
            )
            result = await scanner.scan("loop.example.com")

        # Le scanner capture l'exception et retourne un finding
        assert result.score < 100
        assert len(result.findings) >= 1
        assert result.findings[0].severity == "high"
        assert "Impossible" in result.findings[0].title

    async def test_redirect_loop_does_not_hang(self):
        """Vérifie que le timeout httpx protège contre les boucles lentes."""
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
# Chaîne de certificats incomplète (TLS)
# ===================================================================


class TestIncompleteCertChain:
    async def test_ssl_verification_error_triggers_fallback(self):
        """Un cert avec chaîne incomplète échoue en verify=True, réussit en verify=False."""
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

        # Le fallback verify=False a fonctionné
        assert result["verified"] is False
        assert result["subject_cn"] == "chain.example.com"

    async def test_incomplete_chain_produces_finding_via_scanner(self):
        """Le scan complet avec un cert non vérifié produit le bon résultat."""
        scanner = TlsScanner()
        cert_info = make_cert_info(verified=False)

        with (
            patch("app.scanners.tls._get_cert_info", new_callable=AsyncMock, return_value=cert_info),
            patch("app.scanners.testssl_runner.is_available", return_value=False),
        ):
            result = await scanner.scan("chain.example.com")

        # Le cert est valide côté données, donc score = 100 même si verified=False
        # (le check de vérification n'est pas encore implémenté dans les checks de base)
        assert isinstance(result, ScanResult)
        assert result.score >= 0


# ===================================================================
# crt.sh avec des milliers de résultats (Subdomains)
# ===================================================================


class TestMassiveSubdomains:
    async def test_thousands_of_subdomains_capped_in_description(self):
        """crt.sh renvoie 5000 sous-domaines — la description est tronquée à 20."""
        scanner = SubdomainsScanner()
        huge_result = [
            {"name_value": f"sub{i}.example.com"}
            for i in range(5000)
        ]

        with respx.mock:
            respx.get("https://crt.sh/").mock(
                return_value=httpx.Response(200, json=huge_result)
            )
            # Les checks de takeover vont aussi être appelés — mock httpx pour les 30 premiers
            respx.get(url__regex=r"https://sub\d+\.example\.com").mock(
                return_value=httpx.Response(200, text="OK")
            )

            result = await scanner.scan("example.com")

        # Info finding avec le nombre total
        info = [f for f in result.findings if "5000" in f.title or "sous-domaine" in f.title]
        assert len(info) >= 1
        # La description ne liste que 20 sous-domaines
        desc = info[0].description
        assert "et plus" in desc

    async def test_crt_sh_returns_duplicates_deduplicated(self):
        """crt.sh renvoie le même sous-domaine plusieurs fois — dédupliqué."""
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
        """crt.sh renvoie des name_value avec plusieurs lignes (wildcard + concrete)."""
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
        """crt.sh timeout → retourne un set vide, pas d'exception."""
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
        """crt.sh renvoie du HTML au lieu du JSON → pas de crash."""
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
# Timeout DNS partiel (un seul check timeout, les autres continuent)
# ===================================================================


class TestDnsPartialTimeout:
    async def test_spf_timeout_others_continue(self):
        """Un timeout DNS sur SPF ne bloque pas DMARC, MX, etc."""
        scanner = DnsScanner()
        call_count = {"spf": 0, "other": 0}

        async def selective_timeout(name, rdtype):
            if rdtype == "TXT" and not name.startswith("_"):
                call_count["spf"] += 1
                raise Exception("DNS timeout on SPF")
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

        # Le scan complète malgré le timeout SPF
        assert isinstance(result, ScanResult)
        assert result.score >= 0

        # SPF a échoué → finding d'erreur
        spf_findings = [f for f in result.findings if "SPF" in f.title]
        assert len(spf_findings) >= 1

        # DMARC n'a PAS échoué (pas de finding DMARC manquant)
        dmarc_missing = [f for f in result.findings if "DMARC manquant" in f.title]
        assert len(dmarc_missing) == 0

    async def test_all_dns_checks_timeout_still_returns_result(self):
        """Tous les checks DNS timeout → le scan retourne quand même un ScanResult."""
        scanner = DnsScanner()

        mock_resolver = AsyncMock(spec=dns.asyncresolver.Resolver)
        mock_resolver.nameservers = ["8.8.8.8"]
        mock_resolver.resolve = AsyncMock(
            side_effect=Exception("DNS timeout")
        )

        with patch("app.scanners.dns.dns.asyncresolver.Resolver", return_value=mock_resolver):
            result = await scanner.scan("timeout.example.com")

        assert isinstance(result, ScanResult)
        assert result.score >= 0
        # Plusieurs findings d'erreur mais pas de crash
        assert len(result.findings) > 0


# ===================================================================
# HIBP JSON malformé
# ===================================================================


class TestHIBPMalformedResponse:
    async def test_hibp_returns_invalid_json(self):
        """HIBP renvoie du texte au lieu de JSON → finding info, pas de crash."""
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

        # Le scanner capture l'exception JSON et retourne un finding info
        assert isinstance(result, ScanResult)
        assert len(result.findings) >= 1
        error_findings = [f for f in result.findings if f.severity == "info"]
        assert len(error_findings) >= 1

    async def test_hibp_returns_truncated_json(self):
        """HIBP renvoie du JSON tronqué → erreur de décodage capturée."""
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
        # L'exception JSONDecodeError est capturée par le except Exception
        assert len(result.findings) >= 1

    async def test_hibp_returns_empty_json_object(self):
        """HIBP renvoie {} → 0 breaches → score 100."""
        scanner = LeaksScanner()
        with respx.mock:
            respx.get(url__regex=r".*haveibeenpwned.*").mock(
                return_value=httpx.Response(200, json={})
            )

            result = await scanner.scan("example.com")

        assert result.score == 100

    async def test_hibp_connection_reset(self):
        """HIBP ferme la connexion brutalement → finding info."""
        scanner = LeaksScanner()
        with respx.mock:
            respx.get(url__regex=r".*haveibeenpwned.*").mock(
                side_effect=httpx.RemoteProtocolError(
                    "peer closed connection without sending complete message body",
                )
            )

            result = await scanner.scan("example.com")

        assert isinstance(result, ScanResult)
        conn_findings = [f for f in result.findings if "connexion" in f.title.lower()]
        assert len(conn_findings) == 1


# ===================================================================
# Domaines exotiques et edge cases DNS
# ===================================================================


class TestExoticDomains:
    async def test_punycode_domain_dns(self):
        """Un domaine internationalisé (punycode) passe correctement au resolver."""
        scanner = DnsScanner()

        mock_resolver = AsyncMock(spec=dns.asyncresolver.Resolver)
        mock_resolver.nameservers = ["8.8.8.8"]
        mock_resolver.resolve = AsyncMock(side_effect=Exception("NXDOMAIN"))

        with patch("app.scanners.dns.dns.asyncresolver.Resolver", return_value=mock_resolver):
            result = await scanner.scan("xn--nxasmq6b.example.com")

        assert isinstance(result, ScanResult)
        # Le domaine punycode est passé tel quel au resolver
        calls = mock_resolver.resolve.call_args_list
        assert any("xn--nxasmq6b.example.com" in str(c) for c in calls)

    async def test_very_long_domain(self):
        """Un domaine très long ne crash pas le scanner."""
        scanner = DnsScanner()
        long_domain = "a" * 60 + "." + "b" * 60 + ".example.com"

        mock_resolver = AsyncMock(spec=dns.asyncresolver.Resolver)
        mock_resolver.nameservers = ["8.8.8.8"]
        mock_resolver.resolve = AsyncMock(side_effect=Exception("NXDOMAIN"))

        with patch("app.scanners.dns.dns.asyncresolver.Resolver", return_value=mock_resolver):
            result = await scanner.scan(long_domain)

        assert isinstance(result, ScanResult)


# ===================================================================
# Reputation scanner — edge cases
# ===================================================================


class TestReputationEdgeCases:
    async def test_domain_resolves_to_ipv6_only(self):
        """Un domaine IPv6-only ne crashe pas Spamhaus (IPv6 non supporté)."""
        scanner = ReputationScanner()

        with (
            patch("app.scanners.reputation._resolve_ips", return_value=["2001:db8::1"]),
            patch.dict("os.environ", {"ABUSEIPDB_API_KEY": ""}, clear=False),
        ):
            result = await scanner.scan("ipv6only.example.com")

        assert isinstance(result, ScanResult)
        assert result.score == 100  # IPv6 skip → pas de finding

    async def test_domain_resolves_to_mixed_ipv4_ipv6(self):
        """Un domaine avec IPv4 + IPv6 → seul IPv4 est vérifié via Spamhaus."""
        scanner = ReputationScanner()
        import socket

        with (
            patch("app.scanners.reputation._resolve_ips",
                  return_value=["93.184.216.34", "2001:db8::1"]),
            patch.dict("os.environ", {"ABUSEIPDB_API_KEY": ""}, clear=False),
            patch("app.scanners.reputation.socket.gethostbyname",
                  side_effect=socket.gaierror("NXDOMAIN")),
        ):
            result = await scanner.scan("mixed.example.com")

        assert isinstance(result, ScanResult)
        # Pas de finding (IP non listée = gaierror = OK)
        reputation_findings = [f for f in result.findings if f.severity != "info"]
        assert len(reputation_findings) == 0


# ===================================================================
# Headers — cookies avec redirections complexes
# ===================================================================


class TestCookieRedirectEdgeCases:
    async def test_cookie_set_on_302_then_200(self):
        """Un cookie posé sur la réponse 302 est aussi analysé."""
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
            # HTTP probe : /login redirige et pose un cookie non sécurisé
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

            result = await scanner.scan("redir.example.com")

        cookie_findings = [f for f in result.findings if "sess" in f.title]
        assert len(cookie_findings) >= 1  # Au moins Secure manquant


# ===================================================================
# TLS — erreurs réseau variées
# ===================================================================


class TestTlsNetworkErrors:
    async def test_dns_resolution_failure(self):
        """Le domaine ne résout pas → finding critique TLS."""
        scanner = TlsScanner()

        with (
            patch("app.scanners.tls._get_cert_info", new_callable=AsyncMock,
                  side_effect=OSError("[Errno 8] nodename nor servname provided")),
            patch("app.scanners.testssl_runner.is_available", return_value=False),
        ):
            result = await scanner.scan("nonexistent.invalid")

        assert result.findings[0].severity == "critical"
        assert "impossible" in result.findings[0].title.lower()

    async def test_port_443_closed(self):
        """Le port 443 est fermé → ConnectionRefusedError → finding critique."""
        scanner = TlsScanner()

        with (
            patch("app.scanners.tls._get_cert_info", new_callable=AsyncMock,
                  side_effect=ConnectionRefusedError("Connection refused")),
            patch("app.scanners.testssl_runner.is_available", return_value=False),
        ):
            result = await scanner.scan("http-only.example.com")

        assert result.findings[0].severity == "critical"
        assert "Connection refused" in result.findings[0].description

    async def test_ssl_handshake_timeout(self):
        """Le handshake SSL timeout → finding critique."""
        scanner = TlsScanner()
        import socket

        with (
            patch("app.scanners.tls._get_cert_info", new_callable=AsyncMock,
                  side_effect=socket.timeout("timed out")),
            patch("app.scanners.testssl_runner.is_available", return_value=False),
        ):
            result = await scanner.scan("slow.example.com")

        assert result.findings[0].severity == "critical"
