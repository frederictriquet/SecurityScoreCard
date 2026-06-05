"""Tests for app.scanners.testssl_runner — testssl.sh wrapper."""

import pytest
import json
import os
from unittest.mock import patch, AsyncMock, MagicMock

from app.scanners.testssl_runner import (
    is_available,
    run_testssl,
    _process_entry,
    _VULN_CHECKS,
)
from app.scanners.base import FindingData


# ===================================================================
# is_available
# ===================================================================


class TestIsAvailable:
    def test_available_when_file_exists_and_executable(self):
        with (
            patch("os.path.isfile", return_value=True),
            patch("os.access", return_value=True),
        ):
            assert is_available() is True

    def test_not_available_when_file_missing(self):
        with (
            patch("os.path.isfile", return_value=False),
            patch("os.access", return_value=True),
        ):
            assert is_available() is False

    def test_not_available_when_not_executable(self):
        with (
            patch("os.path.isfile", return_value=True),
            patch("os.access", return_value=False),
        ):
            assert is_available() is False


# ===================================================================
# _process_entry
# ===================================================================


class TestProcessEntry:
    def test_vuln_critical(self):
        findings = []
        _process_entry({
            "id": "heartbleed",
            "severity": "CRITICAL",
            "finding": "VULNERABLE",
        }, findings)
        assert len(findings) == 1
        assert findings[0].severity == "critical"
        assert "Heartbleed" in findings[0].title

    def test_vuln_high(self):
        findings = []
        _process_entry({
            "id": "ROBOT",
            "severity": "HIGH",
            "finding": "VULNERABLE",
        }, findings)
        assert len(findings) == 1
        assert findings[0].severity == "high"
        assert "ROBOT" in findings[0].title

    def test_vuln_warn_mapped_to_medium(self):
        findings = []
        _process_entry({
            "id": "BEAST",
            "severity": "WARN",
            "finding": "VULNERABLE",
        }, findings)
        assert len(findings) == 1
        assert findings[0].severity == "medium"

    def test_vuln_ok_severity_ignored(self):
        findings = []
        _process_entry({
            "id": "heartbleed",
            "severity": "OK",
            "finding": "not vulnerable",
        }, findings)
        assert len(findings) == 0

    def test_cert_chain_issue(self):
        findings = []
        _process_entry({
            "id": "cert_chain_of_trust",
            "severity": "HIGH",
            "finding": "chain incomplete",
        }, findings)
        assert len(findings) == 1
        assert findings[0].severity == "high"
        assert "certificate chain" in findings[0].title.lower()

    def test_intermediate_cert_issue(self):
        findings = []
        _process_entry({
            "id": "intermediate_cert",
            "severity": "MEDIUM",
            "finding": "missing",
        }, findings)
        assert len(findings) == 1
        assert findings[0].severity == "medium"

    def test_ocsp_not_offered(self):
        findings = []
        _process_entry({
            "id": "OCSP_stapling",
            "severity": "INFO",
            "finding": "not offered",
        }, findings)
        assert len(findings) == 1
        assert findings[0].severity == "medium"
        assert "OCSP" in findings[0].title

    def test_ocsp_offered_ok(self):
        findings = []
        _process_entry({
            "id": "OCSP_stapling",
            "severity": "OK",
            "finding": "offered",
        }, findings)
        assert len(findings) == 0

    def test_ct_missing_sct(self):
        findings = []
        _process_entry({
            "id": "certificate_transparency",
            "severity": "INFO",
            "finding": "no SCT found",
        }, findings)
        assert len(findings) == 1
        assert "SCT" in findings[0].title

    def test_ct_sct_present(self):
        findings = []
        _process_entry({
            "id": "certificate_transparency",
            "severity": "OK",
            "finding": "yes (certificate)",
        }, findings)
        assert len(findings) == 0

    def test_unknown_entry_id_no_finding(self):
        findings = []
        _process_entry({
            "id": "unknown_check",
            "severity": "HIGH",
            "finding": "something",
        }, findings)
        assert len(findings) == 0

    def test_missing_severity_no_finding(self):
        findings = []
        _process_entry({
            "id": "heartbleed",
            "finding": "something",
        }, findings)
        assert len(findings) == 0  # severity defaults to "OK"

    def test_all_vuln_checks_produce_finding(self):
        for vuln_id in _VULN_CHECKS:
            findings = []
            _process_entry({
                "id": vuln_id,
                "severity": "HIGH",
                "finding": "VULNERABLE",
            }, findings)
            assert len(findings) == 1, f"No finding for {vuln_id}"

    def test_special_check_takes_priority_over_severity(self):
        """Special checks are evaluated on content, not severity."""
        findings = []
        _process_entry({
            "id": "OCSP_stapling",
            "severity": "OK",  # OK normally ignored
            "finding": "not offered",  # but the flag_if matches
        }, findings)
        assert len(findings) == 1


# ===================================================================
# run_testssl
# ===================================================================


class TestRunTestssl:
    async def test_returns_empty_when_not_available(self):
        with patch("app.scanners.testssl_runner.is_available", return_value=False):
            result = await run_testssl("example.com")
            assert result == []

    async def test_returns_findings_on_success(self):
        json_data = json.dumps([
            {"id": "heartbleed", "severity": "CRITICAL", "finding": "VULNERABLE"},
            {"id": "ROBOT", "severity": "OK", "finding": "not vulnerable"},
        ])

        with (
            patch("app.scanners.testssl_runner.is_available", return_value=True),
            patch("asyncio.create_subprocess_exec") as mock_proc,
            patch("builtins.open", MagicMock(return_value=MagicMock(
                __enter__=MagicMock(return_value=MagicMock(
                    read=MagicMock(return_value=json_data)
                )),
                __exit__=MagicMock(return_value=False),
            ))),
            patch("json.load", return_value=json.loads(json_data)),
            patch("tempfile.NamedTemporaryFile") as mock_tmp,
            patch("os.unlink"),
        ):
            mock_tmp.return_value.__enter__ = MagicMock(
                return_value=MagicMock(name="/tmp/test.json")
            )
            mock_tmp.return_value.__exit__ = MagicMock(return_value=False)

            mock_process = AsyncMock()
            mock_process.wait = AsyncMock(return_value=0)
            mock_proc.return_value = mock_process

            result = await run_testssl("example.com")
            assert len(result) == 1
            assert result[0].severity == "critical"
