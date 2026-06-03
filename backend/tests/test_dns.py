"""Tests pour app.scanners.dns — DnsScanner et tous ses checks."""

import pytest
from unittest.mock import AsyncMock, patch

import dns.resolver
import dns.asyncresolver

from app.scanners.dns import DnsScanner
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
        assert "SPF manquant" in findings[0].title

    async def test_spf_duplicate_records(self, scanner, resolver):
        resolver.resolve = AsyncMock(return_value=FakeDnsAnswer([
            FakeTxtRecord('"v=spf1 include:a.com ~all"'),
            FakeTxtRecord('"v=spf1 include:b.com ~all"'),
        ]))
        findings = []
        await scanner._check_spf("example.com", resolver, findings)
        assert len(findings) == 1
        assert findings[0].severity == "medium"
        assert "dupliqué" in findings[0].title

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
        resolver.resolve = AsyncMock(side_effect=Exception("timeout"))
        findings = []
        await scanner._check_spf("example.com", resolver, findings)
        assert len(findings) == 1
        assert findings[0].severity == "high"
        assert "impossible de résoudre" in findings[0].title.lower()


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
        assert "DMARC manquant" in findings[0].title

    async def test_dmarc_nxdomain(self, scanner, resolver):
        resolver.resolve = AsyncMock(side_effect=dns.resolver.NXDOMAIN())
        findings = []
        await scanner._check_dmarc("example.com", resolver, findings)
        assert len(findings) == 1
        assert findings[0].severity == "high"

    async def test_dmarc_other_exception_silent(self, scanner, resolver):
        resolver.resolve = AsyncMock(side_effect=Exception("network error"))
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
        resolver.resolve = AsyncMock(side_effect=Exception("NXDOMAIN"))
        findings = []
        await scanner._check_dkim("example.com", resolver, findings)
        assert len(findings) == 1
        assert findings[0].severity == "medium"
        assert "DKIM" in findings[0].title

    async def test_dkim_found_on_later_selector(self, scanner, resolver):
        """Simule un échec sur les premiers sélecteurs puis succès sur un suivant."""
        call_count = 0

        async def resolve_side_effect(name, rdtype):
            nonlocal call_count
            call_count += 1
            if "selector1._domainkey" in name:
                return FakeDnsAnswer([FakeTxtRecord('"v=DKIM1; p=..."')])
            raise Exception("NXDOMAIN")

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
        resolver.resolve = AsyncMock(side_effect=Exception("no DNSKEY"))
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
        resolver.resolve = AsyncMock(side_effect=Exception("no MX"))
        findings = []
        await scanner._check_mx("example.com", resolver, findings)
        assert len(findings) == 1
        assert findings[0].severity == "info"


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
        resolver.resolve = AsyncMock(side_effect=Exception("network"))
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
        resolver.resolve = AsyncMock(side_effect=Exception("NXDOMAIN"))
        findings = []
        await scanner._check_mta_sts("example.com", resolver, findings)
        assert len(findings) == 1
        assert findings[0].severity == "low"


# ===================================================================
# DANE/TLSA checks
# ===================================================================


class TestDane:
    async def test_dane_present(self, scanner, resolver):
        """TLSA trouvé pour le premier MX."""
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
        """MX existe mais pas de TLSA."""
        async def resolve_side_effect(name, rdtype):
            if rdtype == "MX":
                return FakeDnsAnswer([FakeMxRecord("mail.example.com.")])
            raise Exception("no TLSA")

        resolver.resolve = resolve_side_effect
        findings = []
        await scanner._check_dane("example.com", resolver, findings)
        assert len(findings) == 1
        assert findings[0].severity == "low"
        assert "DANE" in findings[0].title or "TLSA" in findings[0].title

    async def test_dane_no_mx_skips(self, scanner, resolver):
        """Pas de MX → pas de vérification DANE."""
        resolver.resolve = AsyncMock(side_effect=Exception("no MX"))
        findings = []
        await scanner._check_dane("example.com", resolver, findings)
        assert len(findings) == 0

    async def test_dane_multiple_mx_first_has_tlsa(self, scanner, resolver):
        """Plusieurs MX, TLSA trouvé sur le deuxième."""
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
            raise Exception("no TLSA")

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
        """Les mécanismes qualifiés (+, -, ~, ?) doivent aussi être comptés."""
        includes = " ".join(f"+include:{chr(97 + i)}.com" for i in range(11))
        resolver.resolve = AsyncMock(return_value=FakeDnsAnswer([
            FakeTxtRecord(f'"v=spf1 {includes} ~all"')
        ]))
        findings = []
        await scanner._check_spf_lookups("example.com", resolver, findings)
        assert len(findings) == 1

    async def test_spf_lookups_exception_silent(self, scanner, resolver):
        resolver.resolve = AsyncMock(side_effect=Exception("timeout"))
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
        resolver.resolve = AsyncMock(side_effect=Exception("timeout"))
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
    """Simule un record A pour str(record) → IP."""
    def __init__(self, ip: str):
        self._ip = ip

    def __str__(self):
        return self._ip


class TestAxfr:
    async def test_axfr_no_ns_records(self, scanner, resolver):
        """Pas de NS → pas de vérification AXFR."""
        resolver.resolve = AsyncMock(side_effect=Exception("no NS"))
        findings = []
        await scanner._check_axfr("example.com", resolver, findings)
        assert len(findings) == 0

    async def test_axfr_possible(self, scanner, resolver):
        """Un NS autorise le transfert de zone → finding critical."""
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
        """Aucun NS n'autorise le transfert → pas de finding."""
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
        """Exception pendant le test AXFR → silencieux, continue."""
        async def resolve_side_effect(name, rdtype):
            if rdtype == "NS":
                return [FakeNsRecord("ns1.example.com."), FakeNsRecord("ns2.example.com.")]
            raise Exception("nope")

        resolver.resolve = resolve_side_effect
        findings = []
        with patch("app.scanners.dns._try_axfr", side_effect=Exception("connection refused")):
            await scanner._check_axfr("example.com", resolver, findings)

        assert len(findings) == 0

    def test_try_axfr_returns_false_on_error(self):
        """_try_axfr retourne False si le transfert échoue."""
        from app.scanners.dns import _try_axfr
        with patch("app.scanners.dns.dns.query.xfr", side_effect=Exception("refused")):
            assert _try_axfr("ns.example.com", "example.com") is False


# ===================================================================
# Wildcard DNS checks
# ===================================================================


class TestWildcard:
    async def test_wildcard_detected(self, scanner, resolver):
        """Un sous-domaine aléatoire résout → wildcard détecté."""
        resolver.resolve = AsyncMock(return_value=FakeDnsAnswer([
            FakeTxtRecord("1.2.3.4")
        ]))
        findings = []
        await scanner._check_wildcard("example.com", resolver, findings)
        assert len(findings) == 1
        assert findings[0].severity == "medium"
        assert "Wildcard" in findings[0].title

    async def test_no_wildcard(self, scanner, resolver):
        """Le sous-domaine aléatoire ne résout pas → pas de wildcard."""
        resolver.resolve = AsyncMock(side_effect=dns.resolver.NXDOMAIN())
        findings = []
        await scanner._check_wildcard("example.com", resolver, findings)
        assert len(findings) == 0


# ===================================================================
# NS Redundancy checks
# ===================================================================


class TestNsRedundancy:
    async def test_single_ns(self, scanner, resolver):
        """Un seul NS → finding medium."""
        async def resolve_side_effect(name, rdtype):
            if rdtype == "NS":
                return [FakeNsRecord("ns1.example.com.")]
            raise Exception("no A")

        resolver.resolve = resolve_side_effect
        findings = []
        await scanner._check_ns_redundancy("example.com", resolver, findings)
        assert len(findings) == 1
        assert findings[0].severity == "medium"
        assert "1 serveur" in findings[0].title

    async def test_two_ns_different_networks(self, scanner, resolver):
        """2 NS sur des /24 différents → pas de finding."""
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
        # Pas de finding car les réseaux /24 sont différents
        ns_findings = [f for f in findings if "NS" in f.title or "serveur" in f.title.lower()]
        assert len(ns_findings) == 0

    async def test_two_ns_same_network(self, scanner, resolver):
        """2 NS sur le même /24 → finding medium."""
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
        assert "même réseau" in findings[0].title.lower() or "même sous-réseau" in findings[0].description.lower()

    async def test_ns_resolve_fails(self, scanner, resolver):
        """Impossible de résoudre NS → pas de finding, pas de crash."""
        resolver.resolve = AsyncMock(side_effect=Exception("timeout"))
        findings = []
        await scanner._check_ns_redundancy("example.com", resolver, findings)
        assert len(findings) == 0

    async def test_ns_a_record_fails_gracefully(self, scanner, resolver):
        """NS existent mais leurs A records ne résolvent pas → pas de finding réseau."""
        async def resolve_side_effect(name, rdtype):
            if rdtype == "NS":
                return [FakeNsRecord("ns1.example.com."), FakeNsRecord("ns2.example.com.")]
            if rdtype == "A":
                raise Exception("no A record")
            raise Exception()

        resolver.resolve = resolve_side_effect
        findings = []
        await scanner._check_ns_redundancy("example.com", resolver, findings)
        # Pas de finding "même réseau" car on n'a pas pu résoudre les IPs
        network_findings = [f for f in findings if "réseau" in f.title.lower() or "réseau" in f.description.lower()]
        assert len(network_findings) == 0


# ===================================================================
# Full scan integration
# ===================================================================


class TestDnsFullScan:
    async def test_full_scan_returns_scan_result(self, scanner):
        """Vérifie que scan() retourne un ScanResult même si tout échoue."""
        with patch("app.scanners.dns.dns.asyncresolver.Resolver") as MockResolver:
            mock_instance = MockResolver.return_value
            mock_instance.resolve = AsyncMock(side_effect=Exception("mocked"))
            mock_instance.nameservers = ["8.8.8.8"]
            result = await scanner.scan("example.com")
            assert result.score >= 0
            assert isinstance(result.findings, list)


# ===================================================================
# IDN / Homograph (1.14)
# ===================================================================


def _puny(unicode_label: str) -> str:
    """Encode un label Unicode en Punycode (forme reçue par le scanner)."""
    return unicode_label.encode("idna").decode("ascii")


class TestIdnHomograph:
    async def test_pure_ascii_no_finding(self, scanner, resolver):
        """Un domaine ASCII pur ne déclenche aucun finding homographe."""
        findings = []
        await scanner._check_idn_homograph("example.com", resolver, findings)
        assert findings == []

    async def test_mixed_script_high(self, scanner, resolver):
        """« pаypal » (а cyrillique) mélange latin + cyrillique → high."""
        domain = f"{_puny('pаypal')}.com"
        findings = []
        await scanner._check_idn_homograph(domain, resolver, findings)
        assert len(findings) == 1
        assert findings[0].severity == "high"
        assert "scripts mélangés" in findings[0].title
        assert "CYRILLIC" in findings[0].raw_data and "LATIN" in findings[0].raw_data

    async def test_whole_script_confusable_medium(self, scanner, resolver):
        """Label entièrement cyrillique imitant « apple » → medium."""
        domain = f"{_puny('аррӏе')}.com"
        findings = []
        await scanner._check_idn_homograph(domain, resolver, findings)
        assert len(findings) == 1
        assert findings[0].severity == "medium"
        assert "confusable" in findings[0].title.lower()

    async def test_legit_idn_non_latin_info(self, scanner, resolver):
        """Un IDN légitime en script non latin (CJK) → info, pas d'alerte."""
        domain = f"{_puny('中国')}.com"
        findings = []
        await scanner._check_idn_homograph(domain, resolver, findings)
        assert len(findings) == 1
        assert findings[0].severity == "info"
        assert "internationalisé" in findings[0].title

    async def test_accented_latin_info(self, scanner, resolver):
        """Un label latin accentué (« café ») reste mono-script → info."""
        domain = f"{_puny('café')}.com"
        findings = []
        await scanner._check_idn_homograph(domain, resolver, findings)
        assert len(findings) == 1
        assert findings[0].severity == "info"

    async def test_invalid_punycode_skipped(self, scanner, resolver):
        """Un label xn-- mal formé est ignoré sans crash ni finding."""
        findings = []
        await scanner._check_idn_homograph("xn--!!!invalid.com", resolver, findings)
        assert findings == []

    async def test_no_network_call(self, scanner, resolver):
        """Le check est purement local : il n'interroge jamais le resolver."""
        resolver.resolve = AsyncMock(side_effect=AssertionError("ne doit pas résoudre"))
        findings = []
        await scanner._check_idn_homograph(f"{_puny('pаypal')}.fr", resolver, findings)
        assert len(findings) == 1
