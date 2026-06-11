"""Tests for app.scanners.dns — DnsScanner and all its checks."""

import pytest
from unittest.mock import AsyncMock, patch

import dns.exception
import dns.resolver
import dns.asyncresolver

from app.scanners.dns import DnsScanner, MxProbeResult
from app.scanners.base import FindingData
from tests.conftest import FakeDnsAnswer, FakeTxtRecord, FakeMxRecord


@pytest.fixture
def scanner():
    return DnsScanner()


@pytest.fixture
def resolver():
    return AsyncMock(spec=dns.asyncresolver.Resolver)


# ===================================================================
# SPF checks
# ===================================================================


class TestSpf:
    async def test_spf_present_and_valid(self, scanner, resolver):
        resolver.resolve = AsyncMock(return_value=FakeDnsAnswer([
            FakeTxtRecord('"v=spf1 include:_spf.google.com ~all"')
        ]))
        findings = []
        await scanner._check_spf("example.com", resolver, findings)
        assert len(findings) == 0

    async def test_spf_missing_no_records(self, scanner, resolver):
        resolver.resolve = AsyncMock(return_value=FakeDnsAnswer([
            FakeTxtRecord('"some-other-record"')
        ]))
        findings = []
        await scanner._check_spf("example.com", resolver, findings)
        assert len(findings) == 1
        assert findings[0].severity == "high"
        assert "SPF missing" in findings[0].title

    async def test_spf_duplicate_records(self, scanner, resolver):
        resolver.resolve = AsyncMock(return_value=FakeDnsAnswer([
            FakeTxtRecord('"v=spf1 include:a.com ~all"'),
            FakeTxtRecord('"v=spf1 include:b.com ~all"'),
        ]))
        findings = []
        await scanner._check_spf("example.com", resolver, findings)
        assert len(findings) == 1
        assert findings[0].severity == "medium"
        assert "duplicated" in findings[0].title

    async def test_spf_plus_all_critical(self, scanner, resolver):
        resolver.resolve = AsyncMock(return_value=FakeDnsAnswer([
            FakeTxtRecord('"v=spf1 +all"')
        ]))
        findings = []
        await scanner._check_spf("example.com", resolver, findings)
        assert len(findings) == 1
        assert findings[0].severity == "critical"
        assert "+all" in findings[0].title

    async def test_spf_resolve_exception(self, scanner, resolver):
        resolver.resolve = AsyncMock(side_effect=dns.exception.DNSException("timeout"))
        findings = []
        await scanner._check_spf("example.com", resolver, findings)
        assert len(findings) == 1
        assert findings[0].severity == "high"
        assert "unable to resolve" in findings[0].title.lower()


# ===================================================================
# DMARC checks
# ===================================================================


class TestDmarc:
    async def test_dmarc_present_with_reject(self, scanner, resolver):
        resolver.resolve = AsyncMock(return_value=FakeDnsAnswer([
            FakeTxtRecord('"v=DMARC1; p=reject; rua=mailto:d@example.com"')
        ]))
        findings = []
        await scanner._check_dmarc("example.com", resolver, findings)
        assert len(findings) == 0

    async def test_dmarc_present_with_quarantine(self, scanner, resolver):
        resolver.resolve = AsyncMock(return_value=FakeDnsAnswer([
            FakeTxtRecord('"v=DMARC1; p=quarantine"')
        ]))
        findings = []
        await scanner._check_dmarc("example.com", resolver, findings)
        assert len(findings) == 0

    async def test_dmarc_present_with_none_policy(self, scanner, resolver):
        resolver.resolve = AsyncMock(return_value=FakeDnsAnswer([
            FakeTxtRecord('"v=DMARC1; p=none; rua=mailto:d@example.com"')
        ]))
        findings = []
        await scanner._check_dmarc("example.com", resolver, findings)
        assert len(findings) == 1
        assert findings[0].severity == "medium"
        assert "p=none" in findings[0].title

    async def test_dmarc_missing_no_dmarc_in_txt(self, scanner, resolver):
        resolver.resolve = AsyncMock(return_value=FakeDnsAnswer([
            FakeTxtRecord('"some-other-txt-record"')
        ]))
        findings = []
        await scanner._check_dmarc("example.com", resolver, findings)
        assert len(findings) == 1
        assert findings[0].severity == "high"
        assert "DMARC missing" in findings[0].title

    async def test_dmarc_nxdomain(self, scanner, resolver):
        resolver.resolve = AsyncMock(side_effect=dns.resolver.NXDOMAIN())
        findings = []
        await scanner._check_dmarc("example.com", resolver, findings)
        assert len(findings) == 1
        assert findings[0].severity == "high"

    async def test_dmarc_other_exception_silent(self, scanner, resolver):
        resolver.resolve = AsyncMock(side_effect=dns.exception.DNSException("network error"))
        findings = []
        await scanner._check_dmarc("example.com", resolver, findings)
        assert len(findings) == 0


# ===================================================================
# DKIM checks
# ===================================================================


class TestDkim:
    async def test_dkim_found_on_first_selector(self, scanner, resolver):
        resolver.resolve = AsyncMock(return_value=FakeDnsAnswer([
            FakeTxtRecord('"v=DKIM1; k=rsa; p=MIIB..."')
        ]))
        findings = []
        await scanner._check_dkim("example.com", resolver, findings)
        assert len(findings) == 0

    async def test_dkim_not_found_any_selector(self, scanner, resolver):
        resolver.resolve = AsyncMock(side_effect=dns.resolver.NXDOMAIN())
        findings = []
        await scanner._check_dkim("example.com", resolver, findings)
        assert len(findings) == 1
        assert findings[0].severity == "medium"
        assert "DKIM" in findings[0].title

    async def test_dkim_found_on_later_selector(self, scanner, resolver):
        """Simulate a failure on the first selectors then success on a later one."""
        call_count = 0

        async def resolve_side_effect(name, rdtype):
            nonlocal call_count
            call_count += 1
            if "selector1._domainkey" in name:
                return FakeDnsAnswer([FakeTxtRecord('"v=DKIM1; p=..."')])
            raise dns.resolver.NXDOMAIN()

        resolver.resolve = resolve_side_effect
        findings = []
        await scanner._check_dkim("example.com", resolver, findings)
        assert len(findings) == 0


# ===================================================================
# DNSSEC checks
# ===================================================================


class TestDnssec:
    async def test_dnssec_enabled(self, scanner, resolver):
        resolver.resolve = AsyncMock(return_value=FakeDnsAnswer([
            FakeTxtRecord("DNSKEY_DATA")
        ]))
        findings = []
        await scanner._check_dnssec("example.com", resolver, findings)
        assert len(findings) == 0

    async def test_dnssec_not_enabled(self, scanner, resolver):
        resolver.resolve = AsyncMock(side_effect=dns.resolver.NoAnswer())
        findings = []
        await scanner._check_dnssec("example.com", resolver, findings)
        assert len(findings) == 1
        assert findings[0].severity == "low"
        assert "DNSSEC" in findings[0].title


# ===================================================================
# MX checks
# ===================================================================


class TestMx:
    async def test_mx_present(self, scanner, resolver):
        resolver.resolve = AsyncMock(return_value=FakeDnsAnswer([
            FakeMxRecord("mail.example.com.")
        ]))
        findings = []
        await scanner._check_mx("example.com", resolver, findings)
        assert len(findings) == 0

    async def test_mx_absent(self, scanner, resolver):
        resolver.resolve = AsyncMock(side_effect=dns.resolver.NoAnswer())
        findings = []
        await scanner._check_mx("example.com", resolver, findings)
        assert len(findings) == 1
        assert findings[0].severity == "info"


# ===================================================================
# STARTTLS on MX checks (9.1)
# ===================================================================


class TestStarttlsMx:
    async def test_mx_offers_starttls_no_finding(self, scanner, resolver):
        """Reachable MX advertising STARTTLS → no finding."""
        resolver.resolve = AsyncMock(return_value=FakeDnsAnswer([
            FakeMxRecord("mail.example.com.")
        ]))
        findings = []
        with patch("app.scanners.dns._probe_starttls",
                   return_value=MxProbeResult(starttls=True)):
            await scanner._check_starttls_mx("example.com", resolver, findings)
        assert findings == []

    async def test_mx_without_starttls_high(self, scanner, resolver):
        """Reachable MX that does NOT advertise STARTTLS → high finding."""
        resolver.resolve = AsyncMock(return_value=FakeDnsAnswer([
            FakeMxRecord("mail.example.com.")
        ]))
        findings = []
        with patch("app.scanners.dns._probe_starttls",
                   return_value=MxProbeResult(starttls=False)):
            await scanner._check_starttls_mx("example.com", resolver, findings)
        assert len(findings) == 1
        assert findings[0].severity == "high"
        assert "STARTTLS" in findings[0].title
        assert "mail.example.com" in findings[0].raw_data

    async def test_port25_blocked_not_a_hit(self, scanner, resolver):
        """Connection refused / timeout (probe returns None) → never a high finding."""
        resolver.resolve = AsyncMock(return_value=FakeDnsAnswer([
            FakeMxRecord("mail.example.com.")
        ]))
        findings = []
        with patch("app.scanners.dns._probe_starttls",
                   return_value=MxProbeResult(starttls=None)):
            await scanner._check_starttls_mx("example.com", resolver, findings)
        # Indeterminate: at most an info finding, certainly no high.
        assert all(f.severity != "high" for f in findings)
        assert len(findings) == 1
        assert findings[0].severity == "info"

    async def test_probe_timeout_not_a_hit(self, scanner, resolver):
        """An exception while probing (e.g. wait_for timeout) is treated as indeterminate."""
        resolver.resolve = AsyncMock(return_value=FakeDnsAnswer([
            FakeMxRecord("mail.example.com.")
        ]))
        findings = []
        with patch("app.scanners.dns._probe_starttls", side_effect=TimeoutError("timeout")):
            await scanner._check_starttls_mx("example.com", resolver, findings)
        assert all(f.severity != "high" for f in findings)
        assert len(findings) == 1
        assert findings[0].severity == "info"

    async def test_no_mx_not_applicable(self, scanner, resolver):
        """Domain without MX → not applicable, no finding."""
        resolver.resolve = AsyncMock(side_effect=dns.resolver.NoAnswer())
        findings = []
        with patch("app.scanners.dns._probe_starttls",
                   return_value=MxProbeResult(starttls=False)) as probe:
            await scanner._check_starttls_mx("example.com", resolver, findings)
        assert findings == []
        probe.assert_not_called()

    async def test_mixed_mx_one_missing_starttls_high(self, scanner, resolver):
        """Several MX, one reachable without STARTTLS → high listing only that host."""
        resolver.resolve = AsyncMock(return_value=FakeDnsAnswer([
            FakeMxRecord("mx1.example.com."),
            FakeMxRecord("mx2.example.com."),
        ]))

        def probe_side_effect(host, *args, **kwargs):
            return MxProbeResult(starttls="mx1" in host)

        findings = []
        with patch("app.scanners.dns._probe_starttls", side_effect=probe_side_effect):
            await scanner._check_starttls_mx("example.com", resolver, findings)
        assert len(findings) == 1
        assert findings[0].severity == "high"
        assert "mx2.example.com" in findings[0].raw_data
        assert "mx1.example.com" not in findings[0].raw_data

    async def test_probe_starttls_present(self):
        """STARTTLS advertised and handshake OK → starttls True, cert_ok True."""
        import ssl
        from app.scanners.dns import _probe_starttls
        from unittest.mock import MagicMock

        smtp = MagicMock()
        smtp.ehlo.return_value = (250, b"ok")
        smtp.has_extn.return_value = True
        smtp.__enter__.return_value = smtp
        smtp.__exit__.return_value = False
        with patch("smtplib.SMTP", return_value=smtp):
            result = _probe_starttls("mail.example.com")
        assert result.starttls is True
        assert result.cert_ok is True
        assert result.cert_error is None
        # The handshake must use a verifying context (chain + hostname).
        ctx = smtp.starttls.call_args.kwargs["context"]
        assert isinstance(ctx, ssl.SSLContext)
        assert ctx.verify_mode == ssl.CERT_REQUIRED
        assert ctx.check_hostname is True

    async def test_probe_starttls_absent(self):
        """STARTTLS not advertised → starttls False, no handshake attempted."""
        from app.scanners.dns import _probe_starttls
        from unittest.mock import MagicMock

        smtp = MagicMock()
        smtp.ehlo.return_value = (250, b"ok")
        smtp.has_extn.return_value = False
        smtp.__enter__.return_value = smtp
        smtp.__exit__.return_value = False
        with patch("smtplib.SMTP", return_value=smtp):
            result = _probe_starttls("mail.example.com")
        assert result.starttls is False
        assert result.cert_ok is None
        smtp.starttls.assert_not_called()

    async def test_probe_starttls_connection_error(self):
        """_probe_starttls is indeterminate when the connection fails."""
        from app.scanners.dns import _probe_starttls
        with patch("smtplib.SMTP", side_effect=OSError("connection refused")):
            result = _probe_starttls("mail.example.com")
        assert result.starttls is None
        assert result.cert_ok is None

    async def test_probe_starttls_ehlo_refused(self):
        """A non-2xx EHLO reply → indeterminate (cannot conclude)."""
        from app.scanners.dns import _probe_starttls
        from unittest.mock import MagicMock

        smtp = MagicMock()
        smtp.ehlo.return_value = (554, b"go away")
        smtp.__enter__.return_value = smtp
        smtp.__exit__.return_value = False
        with patch("smtplib.SMTP", return_value=smtp):
            result = _probe_starttls("mail.example.com")
        assert result.starttls is None

    async def test_probe_cert_verification_error(self):
        """A certificate verification failure → cert_ok False with the reason."""
        import ssl
        from app.scanners.dns import _probe_starttls
        from unittest.mock import MagicMock

        exc = ssl.SSLCertVerificationError(
            1, "certificate verify failed: self-signed certificate")
        exc.verify_message = "self-signed certificate"
        smtp = MagicMock()
        smtp.ehlo.return_value = (250, b"ok")
        smtp.has_extn.return_value = True
        smtp.starttls.side_effect = exc
        smtp.__enter__.return_value = smtp
        smtp.__exit__.return_value = False
        with patch("smtplib.SMTP", return_value=smtp):
            result = _probe_starttls("mail.example.com")
        assert result.starttls is True
        assert result.cert_ok is False
        assert result.cert_error == "self-signed certificate"

    async def test_probe_handshake_non_cert_failure_indeterminate(self):
        """A handshake failing for a non-certificate reason → cert indeterminate."""
        from app.scanners.dns import _probe_starttls
        from unittest.mock import MagicMock

        smtp = MagicMock()
        smtp.ehlo.return_value = (250, b"ok")
        smtp.has_extn.return_value = True
        smtp.starttls.side_effect = OSError("connection reset")
        smtp.__enter__.return_value = smtp
        smtp.__exit__.return_value = False
        with patch("smtplib.SMTP", return_value=smtp):
            result = _probe_starttls("mail.example.com")
        assert result.starttls is True
        assert result.cert_ok is None
        assert result.cert_error is None


# ===================================================================
# MX TLS certificate checks (9.2)
# ===================================================================


class TestMxTlsCert:
    async def test_all_mx_valid_cert_info(self, scanner, resolver):
        """All reachable MX present a valid certificate → single info finding."""
        resolver.resolve = AsyncMock(return_value=FakeDnsAnswer([
            FakeMxRecord("mx1.example.com."),
            FakeMxRecord("mx2.example.com."),
        ]))
        findings = []
        with patch("app.scanners.dns._probe_starttls",
                   return_value=MxProbeResult(starttls=True, cert_ok=True)):
            await scanner._check_starttls_mx("example.com", resolver, findings)
        assert len(findings) == 1
        assert findings[0].severity == "info"
        assert "certificate" in findings[0].title.lower()
        assert "mx1.example.com" in findings[0].description
        assert "mx2.example.com" in findings[0].description

    async def test_self_signed_cert_medium(self, scanner, resolver):
        """A self-signed certificate on the MX → medium finding with the reason."""
        resolver.resolve = AsyncMock(return_value=FakeDnsAnswer([
            FakeMxRecord("mail.example.com.")
        ]))
        findings = []
        with patch("app.scanners.dns._probe_starttls",
                   return_value=MxProbeResult(
                       starttls=True, cert_ok=False,
                       cert_error="self-signed certificate")):
            await scanner._check_starttls_mx("example.com", resolver, findings)
        assert len(findings) == 1
        assert findings[0].severity == "medium"
        assert "mail.example.com" in findings[0].description
        assert "self-signed certificate" in findings[0].description
        assert "CA-signed" in findings[0].remediation
        assert "mail.example.com" in findings[0].raw_data

    async def test_hostname_mismatch_medium(self, scanner, resolver):
        """Hostname mismatch → medium finding carrying the verify message."""
        resolver.resolve = AsyncMock(return_value=FakeDnsAnswer([
            FakeMxRecord("mail.example.com.")
        ]))
        reason = "Hostname mismatch, certificate is not valid for 'mail.example.com'"
        findings = []
        with patch("app.scanners.dns._probe_starttls",
                   return_value=MxProbeResult(
                       starttls=True, cert_ok=False, cert_error=reason)):
            await scanner._check_starttls_mx("example.com", resolver, findings)
        assert len(findings) == 1
        assert findings[0].severity == "medium"
        assert reason in findings[0].description

    async def test_expired_cert_medium(self, scanner, resolver):
        """Expired certificate → medium finding carrying the verify message."""
        resolver.resolve = AsyncMock(return_value=FakeDnsAnswer([
            FakeMxRecord("mail.example.com.")
        ]))
        findings = []
        with patch("app.scanners.dns._probe_starttls",
                   return_value=MxProbeResult(
                       starttls=True, cert_ok=False,
                       cert_error="certificate has expired")):
            await scanner._check_starttls_mx("example.com", resolver, findings)
        assert len(findings) == 1
        assert findings[0].severity == "medium"
        assert "certificate has expired" in findings[0].description

    async def test_mixed_valid_and_invalid_lists_only_invalid(self, scanner, resolver):
        """One valid + one invalid MX → one medium finding for the invalid host only."""
        resolver.resolve = AsyncMock(return_value=FakeDnsAnswer([
            FakeMxRecord("mx1.example.com."),
            FakeMxRecord("mx2.example.com."),
        ]))

        def probe_side_effect(host, *args, **kwargs):
            if "mx1" in host:
                return MxProbeResult(starttls=True, cert_ok=True)
            return MxProbeResult(starttls=True, cert_ok=False,
                                 cert_error="self-signed certificate")

        findings = []
        with patch("app.scanners.dns._probe_starttls", side_effect=probe_side_effect):
            await scanner._check_starttls_mx("example.com", resolver, findings)
        assert len(findings) == 1
        assert findings[0].severity == "medium"
        assert "mx2.example.com" in findings[0].description
        assert "mx1.example.com" not in findings[0].raw_data

    async def test_all_unreachable_indeterminate_single_info(self, scanner, resolver):
        """No MX reachable on port 25 → only the shared 'not testable' info finding."""
        resolver.resolve = AsyncMock(return_value=FakeDnsAnswer([
            FakeMxRecord("mail.example.com.")
        ]))
        findings = []
        with patch("app.scanners.dns._probe_starttls",
                   return_value=MxProbeResult(starttls=None)):
            await scanner._check_starttls_mx("example.com", resolver, findings)
        assert len(findings) == 1
        assert findings[0].severity == "info"
        assert "not testable" in findings[0].title.lower()

    async def test_starttls_absent_no_cert_finding(self, scanner, resolver):
        """MX without STARTTLS → only the 9.1 high finding, no 9.2 cert finding."""
        resolver.resolve = AsyncMock(return_value=FakeDnsAnswer([
            FakeMxRecord("mail.example.com.")
        ]))
        findings = []
        with patch("app.scanners.dns._probe_starttls",
                   return_value=MxProbeResult(starttls=False)):
            await scanner._check_starttls_mx("example.com", resolver, findings)
        assert len(findings) == 1
        assert findings[0].severity == "high"
        assert "STARTTLS" in findings[0].title
        assert all("certificate" not in f.title.lower() for f in findings)

    async def test_handshake_failure_indeterminate_no_finding(self, scanner, resolver):
        """STARTTLS advertised but handshake failed for a non-cert reason → nothing."""
        resolver.resolve = AsyncMock(return_value=FakeDnsAnswer([
            FakeMxRecord("mail.example.com.")
        ]))
        findings = []
        with patch("app.scanners.dns._probe_starttls",
                   return_value=MxProbeResult(starttls=True, cert_ok=None)):
            await scanner._check_starttls_mx("example.com", resolver, findings)
        assert findings == []

    async def test_invalid_cert_through_public_scan_path(self, scanner):
        """End-to-end through DnsScanner.scan(): the 9.2 finding reaches the result."""
        async def resolve_side_effect(name, rdtype):
            if rdtype == "MX":
                return FakeDnsAnswer([FakeMxRecord("mail.example.com.")])
            raise dns.resolver.NoAnswer()

        with patch("app.scanners.dns.dns.asyncresolver.Resolver") as MockResolver:
            mock_instance = MockResolver.return_value
            mock_instance.resolve = AsyncMock(side_effect=resolve_side_effect)
            mock_instance.nameservers = ["8.8.8.8"]
            with patch("app.scanners.dns._probe_starttls",
                       return_value=MxProbeResult(
                           starttls=True, cert_ok=False,
                           cert_error="self-signed certificate")):
                result = await scanner.scan("example.com")

        cert_findings = [f for f in result.findings
                         if f.title == "Invalid TLS certificate on MX"]
        assert len(cert_findings) == 1
        assert cert_findings[0].severity == "medium"
        assert "self-signed certificate" in cert_findings[0].description
        # No 9.1 finding: STARTTLS was advertised.
        assert all("STARTTLS" not in f.title for f in result.findings)


# ===================================================================
# CAA checks
# ===================================================================


class TestCaa:
    async def test_caa_present(self, scanner, resolver):
        resolver.resolve = AsyncMock(return_value=FakeDnsAnswer(["caa-record"]))
        findings = []
        await scanner._check_caa("example.com", resolver, findings)
        assert len(findings) == 0

    async def test_caa_missing_no_answer(self, scanner, resolver):
        resolver.resolve = AsyncMock(side_effect=dns.resolver.NoAnswer())
        findings = []
        await scanner._check_caa("example.com", resolver, findings)
        assert len(findings) == 1
        assert findings[0].severity == "medium"
        assert "CAA" in findings[0].title

    async def test_caa_missing_nxdomain(self, scanner, resolver):
        resolver.resolve = AsyncMock(side_effect=dns.resolver.NXDOMAIN())
        findings = []
        await scanner._check_caa("example.com", resolver, findings)
        assert len(findings) == 1
        assert findings[0].severity == "medium"

    async def test_caa_other_exception_silent(self, scanner, resolver):
        resolver.resolve = AsyncMock(side_effect=dns.exception.DNSException("network"))
        findings = []
        await scanner._check_caa("example.com", resolver, findings)
        assert len(findings) == 0


# ===================================================================
# MTA-STS checks
# ===================================================================


class TestMtaSts:
    async def test_mta_sts_present(self, scanner, resolver):
        resolver.resolve = AsyncMock(return_value=FakeDnsAnswer([
            FakeTxtRecord('"v=STSv1; id=20240101"')
        ]))
        findings = []
        await scanner._check_mta_sts("example.com", resolver, findings)
        assert len(findings) == 0

    async def test_mta_sts_missing_no_sts_in_txt(self, scanner, resolver):
        resolver.resolve = AsyncMock(return_value=FakeDnsAnswer([
            FakeTxtRecord('"some-other-record"')
        ]))
        findings = []
        await scanner._check_mta_sts("example.com", resolver, findings)
        assert len(findings) == 1
        assert findings[0].severity == "low"
        assert "MTA-STS" in findings[0].title

    async def test_mta_sts_exception(self, scanner, resolver):
        resolver.resolve = AsyncMock(side_effect=dns.resolver.NXDOMAIN())
        findings = []
        await scanner._check_mta_sts("example.com", resolver, findings)
        assert len(findings) == 1
        assert findings[0].severity == "low"


# ===================================================================
# DANE/TLSA checks
# ===================================================================


class TestDane:
    async def test_dane_present(self, scanner, resolver):
        """TLSA found for the first MX."""
        call_count = 0

        async def resolve_side_effect(name, rdtype):
            nonlocal call_count
            call_count += 1
            if rdtype == "MX":
                return FakeDnsAnswer([FakeMxRecord("mail.example.com.")])
            if rdtype == "TLSA":
                return FakeDnsAnswer([FakeTxtRecord("TLSA_DATA")])
            raise Exception("unexpected")

        resolver.resolve = resolve_side_effect
        findings = []
        await scanner._check_dane("example.com", resolver, findings)
        assert len(findings) == 0

    async def test_dane_missing(self, scanner, resolver):
        """MX exists but no TLSA."""
        async def resolve_side_effect(name, rdtype):
            if rdtype == "MX":
                return FakeDnsAnswer([FakeMxRecord("mail.example.com.")])
            raise dns.resolver.NXDOMAIN()

        resolver.resolve = resolve_side_effect
        findings = []
        await scanner._check_dane("example.com", resolver, findings)
        assert len(findings) == 1
        assert findings[0].severity == "low"
        assert "DANE" in findings[0].title or "TLSA" in findings[0].title

    async def test_dane_no_mx_skips(self, scanner, resolver):
        """No MX → no DANE check."""
        resolver.resolve = AsyncMock(side_effect=dns.resolver.NoAnswer())
        findings = []
        await scanner._check_dane("example.com", resolver, findings)
        assert len(findings) == 0

    async def test_dane_multiple_mx_first_has_tlsa(self, scanner, resolver):
        """Multiple MX, TLSA found on the second one."""
        call_count = 0

        async def resolve_side_effect(name, rdtype):
            nonlocal call_count
            call_count += 1
            if rdtype == "MX":
                return FakeDnsAnswer([
                    FakeMxRecord("mx1.example.com."),
                    FakeMxRecord("mx2.example.com."),
                ])
            if "mx2" in name and rdtype == "TLSA":
                return FakeDnsAnswer([FakeTxtRecord("TLSA")])
            raise dns.resolver.NXDOMAIN()

        resolver.resolve = resolve_side_effect
        findings = []
        await scanner._check_dane("example.com", resolver, findings)
        assert len(findings) == 0


# ===================================================================
# SPF Lookup Count checks
# ===================================================================


class TestSpfLookups:
    async def test_spf_lookups_within_limit(self, scanner, resolver):
        resolver.resolve = AsyncMock(return_value=FakeDnsAnswer([
            FakeTxtRecord('"v=spf1 include:a.com include:b.com mx ~all"')
        ]))
        findings = []
        await scanner._check_spf_lookups("example.com", resolver, findings)
        assert len(findings) == 0  # 3 lookups < 10

    async def test_spf_lookups_exceeds_limit(self, scanner, resolver):
        includes = " ".join(f"include:{chr(97 + i)}.com" for i in range(11))
        resolver.resolve = AsyncMock(return_value=FakeDnsAnswer([
            FakeTxtRecord(f'"v=spf1 {includes} ~all"')
        ]))
        findings = []
        await scanner._check_spf_lookups("example.com", resolver, findings)
        assert len(findings) == 1
        assert findings[0].severity == "medium"
        assert "11" in findings[0].title

    async def test_spf_lookups_exactly_10_ok(self, scanner, resolver):
        includes = " ".join(f"include:{chr(97 + i)}.com" for i in range(10))
        resolver.resolve = AsyncMock(return_value=FakeDnsAnswer([
            FakeTxtRecord(f'"v=spf1 {includes} ~all"')
        ]))
        findings = []
        await scanner._check_spf_lookups("example.com", resolver, findings)
        assert len(findings) == 0

    async def test_spf_lookups_no_spf_record(self, scanner, resolver):
        resolver.resolve = AsyncMock(return_value=FakeDnsAnswer([
            FakeTxtRecord('"not-spf"')
        ]))
        findings = []
        await scanner._check_spf_lookups("example.com", resolver, findings)
        assert len(findings) == 0

    async def test_spf_lookups_counts_a_mx_ptr_exists(self, scanner, resolver):
        resolver.resolve = AsyncMock(return_value=FakeDnsAnswer([
            FakeTxtRecord('"v=spf1 a mx ptr:domain.com exists:%{i}.spf.example.com ~all"')
        ]))
        findings = []
        await scanner._check_spf_lookups("example.com", resolver, findings)
        assert len(findings) == 0  # 4 lookups

    async def test_spf_lookups_counts_redirect(self, scanner, resolver):
        resolver.resolve = AsyncMock(return_value=FakeDnsAnswer([
            FakeTxtRecord('"v=spf1 redirect=_spf.example.com"')
        ]))
        findings = []
        await scanner._check_spf_lookups("example.com", resolver, findings)
        assert len(findings) == 0  # 1 lookup

    async def test_spf_lookups_with_qualified_mechanisms(self, scanner, resolver):
        """Qualified mechanisms (+, -, ~, ?) must also be counted."""
        includes = " ".join(f"+include:{chr(97 + i)}.com" for i in range(11))
        resolver.resolve = AsyncMock(return_value=FakeDnsAnswer([
            FakeTxtRecord(f'"v=spf1 {includes} ~all"')
        ]))
        findings = []
        await scanner._check_spf_lookups("example.com", resolver, findings)
        assert len(findings) == 1

    async def test_spf_lookups_exception_silent(self, scanner, resolver):
        resolver.resolve = AsyncMock(side_effect=dns.exception.DNSException("timeout"))
        findings = []
        await scanner._check_spf_lookups("example.com", resolver, findings)
        assert len(findings) == 0


# ===================================================================
# Full scan integration
# ===================================================================


# ===================================================================
# TLS-RPT checks
# ===================================================================


class TestTlsRpt:
    async def test_tls_rpt_present(self, scanner, resolver):
        resolver.resolve = AsyncMock(return_value=FakeDnsAnswer([
            FakeTxtRecord('"v=TLSRPTv1; rua=mailto:tls@example.com"')
        ]))
        findings = []
        await scanner._check_tls_rpt("example.com", resolver, findings)
        assert len(findings) == 0

    async def test_tls_rpt_missing_no_record(self, scanner, resolver):
        resolver.resolve = AsyncMock(return_value=FakeDnsAnswer([
            FakeTxtRecord('"some-other-record"')
        ]))
        findings = []
        await scanner._check_tls_rpt("example.com", resolver, findings)
        assert len(findings) == 1
        assert findings[0].severity == "low"
        assert "TLS-RPT" in findings[0].title

    async def test_tls_rpt_exception(self, scanner, resolver):
        resolver.resolve = AsyncMock(side_effect=dns.exception.DNSException("timeout"))
        findings = []
        await scanner._check_tls_rpt("example.com", resolver, findings)
        assert len(findings) == 1
        assert findings[0].severity == "low"


# ===================================================================
# BIMI checks
# ===================================================================


class TestBimi:
    async def test_bimi_present(self, scanner, resolver):
        resolver.resolve = AsyncMock(return_value=FakeDnsAnswer([
            FakeTxtRecord('"v=BIMI1; l=https://example.com/logo.svg"')
        ]))
        findings = []
        await scanner._check_bimi("example.com", resolver, findings)
        assert len(findings) == 0

    async def test_bimi_missing(self, scanner, resolver):
        resolver.resolve = AsyncMock(return_value=FakeDnsAnswer([
            FakeTxtRecord('"not-bimi"')
        ]))
        findings = []
        await scanner._check_bimi("example.com", resolver, findings)
        assert len(findings) == 1
        assert findings[0].severity == "info"
        assert "BIMI" in findings[0].title

    async def test_bimi_exception(self, scanner, resolver):
        resolver.resolve = AsyncMock(side_effect=dns.resolver.NXDOMAIN())
        findings = []
        await scanner._check_bimi("example.com", resolver, findings)
        assert len(findings) == 1
        assert "BIMI" in findings[0].title


# ===================================================================
# AXFR (zone transfer) checks
# ===================================================================


class FakeNsRecord:
    def __init__(self, target: str):
        self.target = target


class FakeARecord:
    """Simulate an A record for str(record) → IP."""
    def __init__(self, ip: str):
        self._ip = ip

    def __str__(self):
        return self._ip


class TestAxfr:
    async def test_axfr_no_ns_records(self, scanner, resolver):
        """No NS → no AXFR check."""
        resolver.resolve = AsyncMock(side_effect=dns.resolver.NoAnswer())
        findings = []
        await scanner._check_axfr("example.com", resolver, findings)
        assert len(findings) == 0

    async def test_axfr_possible(self, scanner, resolver):
        """An NS allows zone transfer → critical finding."""
        async def resolve_side_effect(name, rdtype):
            if rdtype == "NS":
                return [FakeNsRecord("ns1.example.com.")]
            raise Exception("nope")

        resolver.resolve = resolve_side_effect
        findings = []
        with patch("app.scanners.dns._try_axfr", return_value=True):
            await scanner._check_axfr("example.com", resolver, findings)

        assert len(findings) == 1
        assert findings[0].severity == "critical"
        assert "AXFR" in findings[0].title

    async def test_axfr_not_possible(self, scanner, resolver):
        """No NS allows the transfer → no finding."""
        async def resolve_side_effect(name, rdtype):
            if rdtype == "NS":
                return [FakeNsRecord("ns1.example.com.")]
            raise Exception("nope")

        resolver.resolve = resolve_side_effect
        findings = []
        with patch("app.scanners.dns._try_axfr", return_value=False):
            await scanner._check_axfr("example.com", resolver, findings)

        assert len(findings) == 0

    async def test_axfr_exception_on_try(self, scanner, resolver):
        """Exception during the AXFR attempt → silent, continues."""
        async def resolve_side_effect(name, rdtype):
            if rdtype == "NS":
                return [FakeNsRecord("ns1.example.com."), FakeNsRecord("ns2.example.com.")]
            raise Exception("nope")

        resolver.resolve = resolve_side_effect
        findings = []
        with patch("app.scanners.dns._try_axfr", side_effect=ConnectionRefusedError("connection refused")):
            await scanner._check_axfr("example.com", resolver, findings)

        assert len(findings) == 0

    def test_try_axfr_returns_false_on_error(self):
        """_try_axfr returns False if the transfer fails."""
        from app.scanners.dns import _try_axfr
        with patch("app.scanners.dns.dns.query.xfr", side_effect=ConnectionRefusedError("refused")):
            assert _try_axfr("ns.example.com", "example.com") is False


# ===================================================================
# Wildcard DNS checks
# ===================================================================


class TestWildcard:
    async def test_wildcard_detected(self, scanner, resolver):
        """A random subdomain resolves → wildcard detected."""
        resolver.resolve = AsyncMock(return_value=FakeDnsAnswer([
            FakeTxtRecord("1.2.3.4")
        ]))
        findings = []
        await scanner._check_wildcard("example.com", resolver, findings)
        assert len(findings) == 1
        assert findings[0].severity == "medium"
        assert "Wildcard" in findings[0].title

    async def test_no_wildcard(self, scanner, resolver):
        """The random subdomain does not resolve → no wildcard."""
        resolver.resolve = AsyncMock(side_effect=dns.resolver.NXDOMAIN())
        findings = []
        await scanner._check_wildcard("example.com", resolver, findings)
        assert len(findings) == 0


# ===================================================================
# NS Redundancy checks
# ===================================================================


class TestNsRedundancy:
    async def test_single_ns(self, scanner, resolver):
        """A single NS → medium finding."""
        async def resolve_side_effect(name, rdtype):
            if rdtype == "NS":
                return [FakeNsRecord("ns1.example.com.")]
            raise dns.resolver.NoAnswer()

        resolver.resolve = resolve_side_effect
        findings = []
        await scanner._check_ns_redundancy("example.com", resolver, findings)
        assert len(findings) == 1
        assert findings[0].severity == "medium"
        assert "1 server" in findings[0].title

    async def test_two_ns_different_networks(self, scanner, resolver):
        """2 NS on different /24 → no finding."""
        async def resolve_side_effect(name, rdtype):
            if rdtype == "NS":
                return [FakeNsRecord("ns1.example.com."), FakeNsRecord("ns2.example.com.")]
            if rdtype == "A":
                if "ns1" in name:
                    return FakeDnsAnswer([FakeARecord("1.2.3.4")])
                return FakeDnsAnswer([FakeARecord("5.6.7.8")])
            raise Exception()

        resolver.resolve = resolve_side_effect
        findings = []
        await scanner._check_ns_redundancy("example.com", resolver, findings)
        # No finding because the /24 networks are different
        ns_findings = [f for f in findings if "NS" in f.title or "server" in f.title.lower()]
        assert len(ns_findings) == 0

    async def test_two_ns_same_network(self, scanner, resolver):
        """2 NS on the same /24 → medium finding."""
        async def resolve_side_effect(name, rdtype):
            if rdtype == "NS":
                return [FakeNsRecord("ns1.example.com."), FakeNsRecord("ns2.example.com.")]
            if rdtype == "A":
                if "ns1" in name:
                    return FakeDnsAnswer([FakeARecord("10.0.1.1")])
                return FakeDnsAnswer([FakeARecord("10.0.1.2")])
            raise Exception()

        resolver.resolve = resolve_side_effect
        findings = []
        await scanner._check_ns_redundancy("example.com", resolver, findings)
        assert len(findings) == 1
        assert "same network" in findings[0].title.lower() or "same /24 subnet" in findings[0].description.lower()

    async def test_ns_resolve_fails(self, scanner, resolver):
        """Cannot resolve NS → no finding, no crash."""
        resolver.resolve = AsyncMock(side_effect=dns.exception.DNSException("timeout"))
        findings = []
        await scanner._check_ns_redundancy("example.com", resolver, findings)
        assert len(findings) == 0

    async def test_ns_a_record_fails_gracefully(self, scanner, resolver):
        """NS exist but their A records do not resolve → no network finding."""
        async def resolve_side_effect(name, rdtype):
            if rdtype == "NS":
                return [FakeNsRecord("ns1.example.com."), FakeNsRecord("ns2.example.com.")]
            if rdtype == "A":
                raise dns.resolver.NoAnswer()
            raise Exception()

        resolver.resolve = resolve_side_effect
        findings = []
        await scanner._check_ns_redundancy("example.com", resolver, findings)
        # No "same network" finding because we could not resolve the IPs
        network_findings = [f for f in findings if "network" in f.title.lower() or "network" in f.description.lower()]
        assert len(network_findings) == 0


# ===================================================================
# Full scan integration
# ===================================================================


class TestDnsFullScan:
    async def test_full_scan_returns_scan_result(self, scanner):
        """Verify that scan() returns a ScanResult even if everything fails."""
        with patch("app.scanners.dns.dns.asyncresolver.Resolver") as MockResolver:
            mock_instance = MockResolver.return_value
            mock_instance.resolve = AsyncMock(side_effect=dns.exception.DNSException("mocked"))
            mock_instance.nameservers = ["8.8.8.8"]
            result = await scanner.scan("example.com")
            assert result.score >= 0
            assert isinstance(result.findings, list)

    async def test_programming_error_propagates(self, scanner, resolver):
        """A non-DNS error (e.g. a refactor bug) must not be silently
        absorbed by the fail-open handling — the orchestrator is the one
        isolating scanner failures."""
        resolver.resolve = AsyncMock(side_effect=TypeError("bug"))
        with pytest.raises(TypeError):
            await scanner._check_caa("example.com", resolver, [])


# ===================================================================
# IDN / Homograph (1.14)
# ===================================================================


def _puny(unicode_label: str) -> str:
    """Encode a Unicode label into Punycode (the form received by the scanner)."""
    return unicode_label.encode("idna").decode("ascii")


class TestIdnHomograph:
    async def test_pure_ascii_no_finding(self, scanner):
        """A pure ASCII domain triggers no homograph finding."""
        findings = []
        await scanner._check_idn_homograph("example.com", findings)
        assert findings == []

    async def test_mixed_script_high(self, scanner):
        """« pаypal » (Cyrillic а) mixes Latin + Cyrillic → high."""
        domain = f"{_puny('pаypal')}.com"
        findings = []
        await scanner._check_idn_homograph(domain, findings)
        assert len(findings) == 1
        assert findings[0].severity == "high"
        assert "mixed scripts" in findings[0].title
        assert "CYRILLIC" in findings[0].raw_data and "LATIN" in findings[0].raw_data

    async def test_whole_script_confusable_medium(self, scanner):
        """Fully Cyrillic label imitating « apple » → medium."""
        domain = f"{_puny('аррӏе')}.com"
        findings = []
        await scanner._check_idn_homograph(domain, findings)
        assert len(findings) == 1
        assert findings[0].severity == "medium"
        assert "confusable" in findings[0].title.lower()

    async def test_legit_idn_non_latin_info(self, scanner):
        """A legitimate IDN in a non-Latin script (CJK) → info, no alert."""
        domain = f"{_puny('中国')}.com"
        findings = []
        await scanner._check_idn_homograph(domain, findings)
        assert len(findings) == 1
        assert findings[0].severity == "info"
        assert "Internationalized" in findings[0].title

    async def test_japanese_han_hiragana_not_high(self, scanner):
        """« 東京めがね.jp » mixes Han + Hiragana ({CJK, HIRAGANA}): this is a
        legitimate Japanese IDN (UTS#39), it must NOT be classified as « high »."""
        domain = f"{_puny('東京めがね')}.jp"
        findings = []
        await scanner._check_idn_homograph(domain, findings)
        assert len(findings) == 1
        assert findings[0].severity == "info"
        assert "Internationalized" in findings[0].title

    async def test_japanese_katakana_prolonged_mark_not_high(self, scanner):
        """« ソニー » (katakana + prolonged sound mark « ー », hence
        {KATAKANA, KATAKANA-HIRAGANA}) is a valid Japanese name → not « high »."""
        domain = f"{_puny('ソニー')}.jp"
        findings = []
        await scanner._check_idn_homograph(domain, findings)
        assert len(findings) == 1
        assert findings[0].severity == "info"

    async def test_korean_han_hangul_not_high(self, scanner):
        """A Korean label mixing Han + Hangul ({CJK, HANGUL}) is legitimate
        (UTS#39) and must not be classified as « high »."""
        domain = f"{_puny('한국例')}.kr"
        findings = []
        await scanner._check_idn_homograph(domain, findings)
        assert len(findings) == 1
        assert findings[0].severity == "info"

    async def test_cjk_cyrillic_still_high(self, scanner):
        """A CJK + Cyrillic mix is NOT a whitelisted combination:
        it must stay « high » (the JP/KR whitelist does not absorb it)."""
        domain = f"{_puny('例е')}.com"
        findings = []
        await scanner._check_idn_homograph(domain, findings)
        assert len(findings) == 1
        assert findings[0].severity == "high"
        assert "CJK" in findings[0].raw_data and "CYRILLIC" in findings[0].raw_data

    async def test_accented_latin_info(self, scanner):
        """An accented Latin label ("café") stays mono-script → info."""
        domain = f"{_puny('café')}.com"
        findings = []
        await scanner._check_idn_homograph(domain, findings)
        assert len(findings) == 1
        assert findings[0].severity == "info"

    async def test_invalid_punycode_skipped(self, scanner):
        """A malformed xn-- label is ignored without crash or finding."""
        findings = []
        await scanner._check_idn_homograph("xn--!!!invalid.com", findings)
        assert findings == []

    async def test_no_resolver_needed(self, scanner):
        """The check is purely local: its signature expects no resolver and
        it produces its finding without any network dependency."""
        findings = []
        await scanner._check_idn_homograph(f"{_puny('pаypal')}.fr", findings)
        assert len(findings) == 1

    async def test_end_to_end_unicode_homograph(self, scanner):
        """End to end: a Unicode homograph pasted as-is by a victim
        passes through the validator (→ Punycode) then triggers the « high » finding.

        This is the real use case: the user does NOT enter the xn-- form, they
        paste « pаypal.com » (Cyrillic « а »). Without the validator's idna
        conversion, the input would be rejected before reaching this scanner.
        """
        from app.schemas import ScanCreate

        # 1. The validator accepts the visible Unicode and converts it to Punycode.
        domain = ScanCreate(domain="pаypal.com").domain
        assert domain.startswith("xn--")  # properly converted to Punycode

        # 2. The scanner receives this form and detects the script mix.
        findings = []
        await scanner._check_idn_homograph(domain, findings)
        assert len(findings) == 1
        assert findings[0].severity == "high"
        assert "CYRILLIC" in findings[0].raw_data and "LATIN" in findings[0].raw_data

    async def test_end_to_end_scan_flags_homograph(self, scanner):
        """End to end via scan(): the homograph domain converted by the
        validator does surface in the DNS orchestrator's findings."""
        from app.schemas import ScanCreate

        domain = ScanCreate(domain="pаypal.com").domain
        with patch("app.scanners.dns.dns.asyncresolver.Resolver") as MockResolver:
            mock_instance = MockResolver.return_value
            mock_instance.resolve = AsyncMock(side_effect=dns.exception.DNSException("mocked"))
            mock_instance.nameservers = ["8.8.8.8"]
            result = await scanner.scan(domain)

        homograph = [f for f in result.findings if "homograph" in f.title.lower()]
        assert len(homograph) == 1
        assert homograph[0].severity == "high"
