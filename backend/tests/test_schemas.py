"""Tests pour app.schemas — validation du domaine et sérialisation."""

import pytest
from pydantic import ValidationError

from app.schemas import ScanCreate, FindingOut, ScanModuleOut, ScanOut, ScanSummary


# ===================================================================
# ScanCreate — validation du domaine
# ===================================================================


class TestScanCreateValidDomains:
    @pytest.mark.parametrize("domain", [
        "example.com",
        "sub.example.com",
        "deep.sub.example.com",
        "example.co.uk",
        "a.io",
        "test-site.org",
        "my-long-subdomain.example.com",
    ])
    def test_valid_domains(self, domain):
        scan = ScanCreate(domain=domain)
        assert scan.domain == domain.lower()

    def test_strips_whitespace(self):
        scan = ScanCreate(domain="  example.com  ")
        assert scan.domain == "example.com"

    def test_removes_https_prefix(self):
        scan = ScanCreate(domain="https://example.com")
        assert scan.domain == "example.com"

    def test_removes_http_prefix(self):
        scan = ScanCreate(domain="http://example.com")
        assert scan.domain == "example.com"

    def test_removes_trailing_slash(self):
        scan = ScanCreate(domain="example.com/")
        assert scan.domain == "example.com"

    def test_removes_https_and_trailing_slash(self):
        scan = ScanCreate(domain="https://example.com/")
        assert scan.domain == "example.com"

    def test_lowercases_domain(self):
        scan = ScanCreate(domain="EXAMPLE.COM")
        assert scan.domain == "example.com"

    def test_mixed_case_with_prefix(self):
        scan = ScanCreate(domain="HTTPS://Example.COM/")
        assert scan.domain == "example.com"


class TestScanCreateIdn:
    """Conversion Punycode des domaines internationalisés / homographes.

    Sans cette conversion, un homographe Unicode collé tel quel par une victime
    serait rejeté avant d'atteindre le scanner homographe (cf. ticket 1.14).
    """

    def test_unicode_homograph_converted_to_punycode(self):
        # « pаypal.com » avec un « а » cyrillique : doit être accepté et encodé.
        scan = ScanCreate(domain="pаypal.com")
        assert scan.domain == "xn--pypal-4ve.com"

    def test_legit_idn_converted_to_punycode(self):
        # IDN légitime (CJK) : accepté et encodé en Punycode.
        scan = ScanCreate(domain="中国.com")
        assert scan.domain == "xn--fiqs8s.com"

    def test_accented_latin_converted(self):
        scan = ScanCreate(domain="café.com")
        assert scan.domain == "xn--caf-dma.com"

    def test_unicode_with_prefix_and_slash(self):
        scan = ScanCreate(domain="https://pаypal.com/")
        assert scan.domain == "xn--pypal-4ve.com"

    def test_ascii_domain_unchanged_by_idna(self):
        # The idna conversion must not alter a pure ASCII domain.
        scan = ScanCreate(domain="example.com")
        assert scan.domain == "example.com"

    @pytest.mark.parametrize("domain,expected", [
        # Internationalized TLDs (ccTLD/gTLD IDN): the leading label becomes a
        # Punycode "xn--…" with digits/hyphens, which must be accepted.
        ("президент.рф", "xn--d1abbgf6aiiy.xn--p1ai"),
        ("x.中国", "x.xn--fiqs8s"),
        ("例е.テсть", "xn--e1a5869a.xn--q1ac4az709a"),
    ])
    def test_internationalized_tld_accepted(self, domain, expected):
        # Without Punycode TLD support, these domains were wrongly rejected,
        # making homograph detection ineffective on the ccTLD/gTLD IDN space.
        scan = ScanCreate(domain=domain)
        assert scan.domain == expected


class TestScanCreateHomographRejection:
    """Rejection of a homograph domain: the error explains the danger.

    When a suspicious non-ASCII domain cannot be validated (e.g. confusable label
    without TLD, homograph pasted with a path), the validator must not settle for
    a terse "Domaine invalide": it must explain what a homograph attack is and why
    it is dangerous (cf. IDN ticket).
    """

    def _error_message(self, domain):
        with pytest.raises(ValidationError) as exc_info:
            ScanCreate(domain=domain)
        return exc_info.value.errors()[0]["msg"]

    def test_confusable_only_label_explained(self):
        # "gооgle" (Cyrillic o) without TLD: rejected, but with an explanation.
        msg = self._error_message("gооgle")
        assert "homograph" in msg.lower()
        assert "Invalid domain" not in msg
        assert "CYRILLIC" in msg  # names the suspicious character(s)

    def test_homograph_with_path_explained(self):
        # Homograph pasted with a path: rejected (path), but explained.
        msg = self._error_message("pаypal.com/login")
        assert "homograph" in msg.lower()
        assert "IDN spoofing" in msg

    def test_explanation_mentions_punycode_form(self):
        # The explanation reveals the real Punycode form when it is computable.
        msg = self._error_message("gооgle")
        assert "xn--" in msg

    def test_explanation_states_why_dangerous(self):
        # "why it is a problem": phishing / impersonation of a legitimate site.
        msg = self._error_message("аррӏе")  # "apple" entirely in Cyrillic, no TLD
        assert "homograph" in msg.lower()
        assert any(w in msg.lower() for w in ("legitimate", "phishing", "credentials"))

    def test_ascii_invalid_domain_stays_generic(self):
        # An invalid ASCII domain keeps the generic message (not a homograph).
        # (Pydantic prefixes the message with "Value error, " hence the `in`.)
        msg = self._error_message("exam ple.com")
        assert "Invalid domain" in msg
        assert "homograph" not in msg.lower()

    def test_accented_latin_without_tld_stays_generic(self):
        # Single-script accented Latin ("café" without TLD) is not a homograph:
        # generic message, no false "homograph" alert.
        msg = self._error_message("café")
        assert "Invalid domain" in msg
        assert "homograph" not in msg.lower()

    def test_legit_idn_without_tld_stays_generic(self):
        # Legitimate non-confusable IDN (CJK) without TLD → generic, no alert.
        msg = self._error_message("中国")
        assert "Invalid domain" in msg
        assert "homograph" not in msg.lower()


class TestScanCreateInvalidDomains:
    @pytest.mark.parametrize("domain", [
        "",
        "   ",
        "not_valid",
        "example",
        "exam ple.com",
        "-example.com",
        "example-.com",
        ".example.com",
        "example..com",
        "example.com:8080",
        "http://example.com/path/to/page",
        "ftp://example.com",
        "192.168.1.1",
        "example.c",       # TLD trop court (1 seule lettre)
        "@example.com",
        "exam!ple.com",
    ])
    def test_invalid_domains_raise_validation_error(self, domain):
        with pytest.raises(ValidationError):
            ScanCreate(domain=domain)


# ===================================================================
# FindingOut — from_attributes
# ===================================================================


class TestFindingOut:
    def test_from_dict(self):
        data = {
            "id": "abc",
            "severity": "high",
            "title": "Test",
            "description": "Desc",
            "remediation": None,
        }
        f = FindingOut(**data)
        assert f.id == "abc"
        assert f.severity == "high"

    def test_with_remediation(self):
        f = FindingOut(
            id="x", severity="low", title="T", description="D", remediation="Fix"
        )
        assert f.remediation == "Fix"


# ===================================================================
# ScanModuleOut
# ===================================================================


class TestScanModuleOut:
    def test_minimal(self):
        m = ScanModuleOut(
            id="m1",
            name="dns",
            status="completed",
            score=95,
            weight=0.2,
            started_at=None,
            completed_at=None,
        )
        assert m.name == "dns"
        assert m.findings == []

    def test_with_findings(self):
        finding = FindingOut(
            id="f1", severity="high", title="T", description="D", remediation=None
        )
        m = ScanModuleOut(
            id="m1",
            name="tls",
            status="completed",
            score=80,
            weight=0.2,
            started_at=None,
            completed_at=None,
            findings=[finding],
        )
        assert len(m.findings) == 1


# ===================================================================
# ScanOut
# ===================================================================


class TestScanOut:
    def test_minimal(self):
        from datetime import datetime, timezone

        s = ScanOut(
            id="s1",
            domain="example.com",
            status="pending",
            score=None,
            grade=None,
            started_at=None,
            completed_at=None,
            created_at=datetime.now(timezone.utc),
        )
        assert s.modules == []
        assert s.status == "pending"


# ===================================================================
# ScanSummary
# ===================================================================


class TestScanSummary:
    def test_fields(self):
        from datetime import datetime, timezone

        s = ScanSummary(
            id="s1",
            domain="example.com",
            status="completed",
            score=85,
            grade="B",
            created_at=datetime.now(timezone.utc),
        )
        assert s.grade == "B"
        assert s.score == 85
