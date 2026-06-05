"""Tests for app.scanners.testssl_runner — testssl.sh parsing and orchestration."""

import json
import os
import pytest
from unittest.mock import patch, AsyncMock, MagicMock

from app.scanners.testssl_runner import (
    _process_entry,
    run_testssl,
    is_available,
    _SEVERITY_MAP,
    _VULN_CHECKS,
    _CERT_CHECKS,
    _SPECIAL_CHECKS,
)
from app.scanners.base import FindingData


# ===================================================================
# _process_entry — TLS vulnerabilities
# ===================================================================


class TestProcessEntryVulnerabilities:
    def test_heartbleed_critical(self):
        """Heartbleed with severity CRITICAL → critical finding."""
        findings = []
        _process_entry({"id": "heartbleed", "severity": "CRITICAL", "finding": "VULNERABLE"}, findings)
        assert len(findings) == 1
        assert findings[0].severity == "critical"
        assert "Heartbleed" in findings[0].title
        assert "CVE-2014-0160" in findings[0].title

    def test_poodle_high(self):
        """POODLE with severity HIGH → high finding."""
        findings = []
        _process_entry({"id": "POODLE_SSL", "severity": "HIGH", "finding": "VULNERABLE"}, findings)
        assert len(findings) == 1
        assert findings[0].severity == "high"
        assert "POODLE" in findings[0].title

    def test_drown_critical(self):
        """DROWN with severity CRITICAL → critical finding."""
        findings = []
        _process_entry({"id": "DROWN", "severity": "CRITICAL", "finding": "VULNERABLE"}, findings)
        assert len(findings) == 1
        assert findings[0].severity == "critical"
        assert "DROWN" in findings[0].title
        assert "CVE-2016-0800" in findings[0].title

    def test_beast_medium(self):
        """BEAST with severity MEDIUM → medium finding."""
        findings = []
        _process_entry({"id": "BEAST", "severity": "MEDIUM", "finding": "VULNERABLE"}, findings)
        assert len(findings) == 1
        assert findings[0].severity == "medium"
        assert "BEAST" in findings[0].title

    def test_rc4_high(self):
        """RC4 with severity HIGH → high finding."""
        findings = []
        _process_entry({"id": "RC4", "severity": "HIGH", "finding": "offered"}, findings)
        assert len(findings) == 1
        assert findings[0].severity == "high"
        assert "RC4" in findings[0].title

    def test_all_vuln_checks_have_required_fields(self):
        """Each entry in _VULN_CHECKS has title, description, remediation."""
        for vuln_id, info in _VULN_CHECKS.items():
            assert "title" in info, f"{vuln_id} manque 'title'"
            assert "description" in info, f"{vuln_id} manque 'description'"
            assert "remediation" in info, f"{vuln_id} manque 'remediation'"

    @pytest.mark.parametrize("vuln_id", list(_VULN_CHECKS.keys()))
    def test_each_vuln_produces_finding(self, vuln_id):
        """Each known vulnerability produces a finding when severity is mapped."""
        findings = []
        _process_entry({"id": vuln_id, "severity": "HIGH", "finding": "VULNERABLE"}, findings)
        assert len(findings) == 1
        assert findings[0].severity == "high"
        assert findings[0].title == _VULN_CHECKS[vuln_id]["title"]
        assert findings[0].remediation == _VULN_CHECKS[vuln_id]["remediation"]


# ===================================================================
# _process_entry — severity mapping
# ===================================================================


class TestProcessEntrySeverityMapping:
    @pytest.mark.parametrize("testssl_sev,expected", [
        ("CRITICAL", "critical"),
        ("HIGH", "high"),
        ("MEDIUM", "medium"),
        ("LOW", "low"),
        ("WARN", "medium"),
    ])
    def test_severity_mapping(self, testssl_sev, expected):
        """Each testssl level is correctly mapped."""
        findings = []
        _process_entry({"id": "heartbleed", "severity": testssl_sev, "finding": "VULNERABLE"}, findings)
        assert findings[0].severity == expected

    def test_ok_severity_no_finding(self):
        """Severity OK → no finding."""
        findings = []
        _process_entry({"id": "heartbleed", "severity": "OK", "finding": "not vulnerable"}, findings)
        assert len(findings) == 0

    def test_info_severity_no_finding(self):
        """Severity INFO → no finding."""
        findings = []
        _process_entry({"id": "heartbleed", "severity": "INFO", "finding": "something"}, findings)
        assert len(findings) == 0

    def test_unknown_severity_no_finding(self):
        """Unknown severity → no finding."""
        findings = []
        _process_entry({"id": "heartbleed", "severity": "UNKNOWN", "finding": "?"}, findings)
        assert len(findings) == 0

    def test_empty_severity_no_finding(self):
        """Severity absent (defaults to 'OK') → no finding."""
        findings = []
        _process_entry({"id": "heartbleed", "finding": "not vulnerable"}, findings)
        assert len(findings) == 0


# ===================================================================
# _process_entry — cert chain checks
# ===================================================================


class TestProcessEntryCertChecks:
    def test_cert_chain_of_trust_invalid(self):
        """Invalid certificate chain → finding."""
        findings = []
        _process_entry({"id": "cert_chain_of_trust", "severity": "HIGH", "finding": "NOT ok"}, findings)
        assert len(findings) == 1
        assert "Chaîne de certificats" in findings[0].title
        assert findings[0].severity == "high"

    def test_intermediate_cert_missing(self):
        """Missing intermediate certificate → finding."""
        findings = []
        _process_entry({"id": "intermediate_cert", "severity": "MEDIUM", "finding": "missing"}, findings)
        assert len(findings) == 1
        assert "intermédiaire" in findings[0].title.lower()
        assert findings[0].severity == "medium"

    def test_cert_check_ok_no_finding(self):
        """Cert check with severity OK → no finding."""
        findings = []
        _process_entry({"id": "cert_chain_of_trust", "severity": "OK", "finding": "all good"}, findings)
        assert len(findings) == 0


# ===================================================================
# _process_entry — special checks (OCSP, CT)
# ===================================================================


class TestProcessEntrySpecialChecks:
    def test_ocsp_not_offered(self):
        """OCSP stapling 'not offered' → medium finding."""
        findings = []
        _process_entry({
            "id": "OCSP_stapling",
            "severity": "INFO",
            "finding": "not offered",
        }, findings)
        assert len(findings) == 1
        assert findings[0].severity == "medium"
        assert "OCSP" in findings[0].title

    def test_ocsp_offered_no_finding(self):
        """OCSP stapling offered → no finding."""
        findings = []
        _process_entry({
            "id": "OCSP_stapling",
            "severity": "OK",
            "finding": "offered",
        }, findings)
        assert len(findings) == 0

    def test_ct_no_sct(self):
        """Certificate Transparency without SCT → medium finding."""
        findings = []
        _process_entry({
            "id": "certificate_transparency",
            "severity": "INFO",
            "finding": "no SCT found",
        }, findings)
        assert len(findings) == 1
        assert findings[0].severity == "medium"
        assert "Certificate Transparency" in findings[0].title

    def test_ct_sct_present_no_finding(self):
        """Certificate Transparency with SCT → no finding."""
        findings = []
        _process_entry({
            "id": "certificate_transparency",
            "severity": "OK",
            "finding": "yes (SCT in certificate)",
        }, findings)
        assert len(findings) == 0

    def test_special_check_returns_early(self):
        """Special checks return before the vuln/cert checks (even with severity HIGH)."""
        findings = []
        _process_entry({
            "id": "OCSP_stapling",
            "severity": "HIGH",
            "finding": "offered",
        }, findings)
        # OCSP offered → no finding, even with severity HIGH
        assert len(findings) == 0


# ===================================================================
# _process_entry — unknown / malformed entries
# ===================================================================


class TestProcessEntryEdgeCases:
    def test_unknown_entry_id_ignored(self):
        """Unknown ID with severity HIGH → no finding."""
        findings = []
        _process_entry({"id": "some_unknown_check", "severity": "HIGH", "finding": "something"}, findings)
        assert len(findings) == 0

    def test_empty_entry(self):
        """Empty entry → no crash."""
        findings = []
        _process_entry({}, findings)
        assert len(findings) == 0

    def test_missing_id(self):
        """Entry without id → no crash."""
        findings = []
        _process_entry({"severity": "HIGH", "finding": "test"}, findings)
        assert len(findings) == 0

    def test_multiple_entries_accumulate(self):
        """Multiple entries → accumulated findings."""
        findings = []
        _process_entry({"id": "heartbleed", "severity": "CRITICAL", "finding": "VULNERABLE"}, findings)
        _process_entry({"id": "DROWN", "severity": "CRITICAL", "finding": "VULNERABLE"}, findings)
        _process_entry({"id": "BEAST", "severity": "MEDIUM", "finding": "VULNERABLE"}, findings)
        assert len(findings) == 3
        assert findings[0].title != findings[1].title


# ===================================================================
# run_testssl — orchestration
# ===================================================================


class TestRunTestssl:
    async def test_not_available_returns_empty(self):
        """testssl.sh unavailable → empty list."""
        with patch("app.scanners.testssl_runner.is_available", return_value=False):
            result = await run_testssl("example.com")
        assert result == []

    async def test_successful_run_parses_json(self):
        """Successful run → parse the JSON and return the findings."""
        json_data = [
            {"id": "heartbleed", "severity": "CRITICAL", "finding": "VULNERABLE"},
            {"id": "POODLE_SSL", "severity": "HIGH", "finding": "VULNERABLE"},
            {"id": "RC4", "severity": "OK", "finding": "not offered"},
        ]

        mock_proc = AsyncMock()
        mock_proc.wait = AsyncMock(return_value=0)

        with (
            patch("app.scanners.testssl_runner.is_available", return_value=True),
            patch("asyncio.create_subprocess_exec", return_value=mock_proc),
            patch("builtins.open", create=True) as mock_open,
            patch("os.unlink"),
        ):
            mock_open.return_value.__enter__ = MagicMock(
                return_value=MagicMock(read=MagicMock(return_value=json.dumps(json_data)))
            )
            mock_open.return_value.__exit__ = MagicMock(return_value=False)
            # Patch json.load to return our data
            with patch("json.load", return_value=json_data):
                result = await run_testssl("example.com")

        assert len(result) == 2  # heartbleed + POODLE (RC4 OK ignored)
        assert result[0].title == "Heartbleed (CVE-2014-0160)"
        assert result[1].title == "POODLE (SSLv3 CBC)"

    async def test_timeout_returns_empty(self):
        """Timeout → empty list, no crash."""
        import asyncio as aio

        mock_proc = AsyncMock()
        mock_proc.wait = AsyncMock(side_effect=aio.TimeoutError())

        with (
            patch("app.scanners.testssl_runner.is_available", return_value=True),
            patch("asyncio.create_subprocess_exec", return_value=mock_proc),
            patch("os.unlink"),
        ):
            result = await run_testssl("example.com")

        assert result == []

    async def test_invalid_json_returns_empty(self):
        """Invalid JSON → empty list."""
        mock_proc = AsyncMock()
        mock_proc.wait = AsyncMock(return_value=0)

        with (
            patch("app.scanners.testssl_runner.is_available", return_value=True),
            patch("asyncio.create_subprocess_exec", return_value=mock_proc),
            patch("builtins.open", create=True) as mock_open,
            patch("json.load", side_effect=json.JSONDecodeError("bad", "", 0)),
            patch("os.unlink"),
        ):
            mock_open.return_value.__enter__ = MagicMock(return_value=MagicMock())
            mock_open.return_value.__exit__ = MagicMock(return_value=False)
            result = await run_testssl("example.com")

        assert result == []

    async def test_json_file_not_found_returns_empty(self):
        """JSON file absent (testssl did not write it) → empty list."""
        mock_proc = AsyncMock()
        mock_proc.wait = AsyncMock(return_value=0)

        with (
            patch("app.scanners.testssl_runner.is_available", return_value=True),
            patch("asyncio.create_subprocess_exec", return_value=mock_proc),
            patch("builtins.open", side_effect=FileNotFoundError("no such file")),
            patch("os.unlink"),
        ):
            result = await run_testssl("example.com")

        assert result == []

    async def test_tempfile_cleanup_on_success(self):
        """The temporary file is cleaned up after a successful run."""
        mock_proc = AsyncMock()
        mock_proc.wait = AsyncMock(return_value=0)

        with (
            patch("app.scanners.testssl_runner.is_available", return_value=True),
            patch("asyncio.create_subprocess_exec", return_value=mock_proc),
            patch("builtins.open", create=True) as mock_open,
            patch("json.load", return_value=[]),
            patch("os.unlink") as mock_unlink,
        ):
            mock_open.return_value.__enter__ = MagicMock(return_value=MagicMock())
            mock_open.return_value.__exit__ = MagicMock(return_value=False)
            await run_testssl("example.com")

        mock_unlink.assert_called_once()

    async def test_tempfile_cleanup_on_error(self):
        """The temporary file is cleaned up even on error."""
        mock_proc = AsyncMock()
        mock_proc.wait = AsyncMock(side_effect=Exception("crash"))

        with (
            patch("app.scanners.testssl_runner.is_available", return_value=True),
            patch("asyncio.create_subprocess_exec", return_value=mock_proc),
            patch("os.unlink") as mock_unlink,
        ):
            # Is the unexpected exception caught by the generic except?
            # No — only TimeoutError and JSONDecodeError/FileNotFoundError are caught
            # A generic Exception will propagate... unless we wrap it
            try:
                await run_testssl("example.com")
            except Exception:
                pass

        # unlink is in the finally block, so always called
        mock_unlink.assert_called_once()


# ===================================================================
# is_available
# ===================================================================


class TestIsAvailable:
    def test_file_exists_and_executable(self):
        """File exists and is executable → True."""
        with (
            patch("os.path.isfile", return_value=True),
            patch("os.access", return_value=True),
        ):
            assert is_available() is True

    def test_file_not_found(self):
        """File does not exist → False."""
        with patch("os.path.isfile", return_value=False):
            assert is_available() is False

    def test_file_not_executable(self):
        """File exists but is not executable → False."""
        with (
            patch("os.path.isfile", return_value=True),
            patch("os.access", return_value=False),
        ):
            assert is_available() is False
