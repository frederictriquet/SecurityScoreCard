"""Tests for app.scanners.ports — PortsScanner, nmap, WHOIS."""

import json
import os
import tempfile
import pytest
from unittest.mock import patch, AsyncMock, MagicMock
from datetime import datetime, timedelta

from app.scanners.ports import (
    PortsScanner,
    is_available,
    _run_nmap,
    _parse_nmap_xml,
    _check_whois,
    _whois_sync,
    DANGEROUS_PORTS,
)
from app.scanners.base import FindingData


@pytest.fixture
def scanner():
    return PortsScanner()


# ===================================================================
# is_available
# ===================================================================


class TestIsAvailable:
    def test_nmap_exists_and_executable(self):
        with patch("os.path.isfile", return_value=True), patch("os.access", return_value=True):
            assert is_available() is True

    def test_nmap_not_found(self):
        with patch("os.path.isfile", return_value=False):
            assert is_available() is False

    def test_nmap_not_executable(self):
        with patch("os.path.isfile", return_value=True), patch("os.access", return_value=False):
            assert is_available() is False


# ===================================================================
# _parse_nmap_xml
# ===================================================================


NMAP_XML_TEMPLATE = """\
<?xml version="1.0"?>
<nmaprun>
  <host>
    <ports>
      {ports}
    </ports>
  </host>
</nmaprun>
"""


def _make_port_xml(portid, proto="tcp", state="open", service=None, product=None, version=None):
    svc = ""
    if service:
        attrs = f'name="{service}"'
        if product:
            attrs += f' product="{product}"'
        if version:
            attrs += f' version="{version}"'
        svc = f"<service {attrs}/>"
    return f'<port protocol="{proto}" portid="{portid}"><state state="{state}"/>{svc}</port>'


class TestParseNmapXml:
    def test_single_open_port(self):
        xml = NMAP_XML_TEMPLATE.format(ports=_make_port_xml(22, service="ssh"))
        with tempfile.NamedTemporaryFile(mode="w", suffix=".xml", delete=False) as f:
            f.write(xml)
            f.flush()
            result = _parse_nmap_xml(f.name)
            os.unlink(f.name)

        assert len(result) == 1
        assert result[0]["port"] == 22
        assert result[0]["proto"] == "tcp"
        assert result[0]["state"] == "open"
        assert result[0]["service"] == "ssh"

    def test_multiple_ports(self):
        ports = _make_port_xml(80, service="http") + _make_port_xml(443, service="https")
        xml = NMAP_XML_TEMPLATE.format(ports=ports)
        with tempfile.NamedTemporaryFile(mode="w", suffix=".xml", delete=False) as f:
            f.write(xml)
            f.flush()
            result = _parse_nmap_xml(f.name)
            os.unlink(f.name)

        assert len(result) == 2
        assert {p["port"] for p in result} == {80, 443}

    def test_closed_port_included(self):
        """Closed ports are included in the parsing (filtering done elsewhere)."""
        xml = NMAP_XML_TEMPLATE.format(ports=_make_port_xml(22, state="closed"))
        with tempfile.NamedTemporaryFile(mode="w", suffix=".xml", delete=False) as f:
            f.write(xml)
            f.flush()
            result = _parse_nmap_xml(f.name)
            os.unlink(f.name)

        assert len(result) == 1
        assert result[0]["state"] == "closed"

    def test_service_with_version(self):
        xml = NMAP_XML_TEMPLATE.format(
            ports=_make_port_xml(22, service="ssh", product="OpenSSH", version="8.9")
        )
        with tempfile.NamedTemporaryFile(mode="w", suffix=".xml", delete=False) as f:
            f.write(xml)
            f.flush()
            result = _parse_nmap_xml(f.name)
            os.unlink(f.name)

        assert result[0]["version"] == "OpenSSH 8.9"

    def test_service_product_without_version(self):
        xml = NMAP_XML_TEMPLATE.format(
            ports=_make_port_xml(80, service="http", product="nginx")
        )
        with tempfile.NamedTemporaryFile(mode="w", suffix=".xml", delete=False) as f:
            f.write(xml)
            f.flush()
            result = _parse_nmap_xml(f.name)
            os.unlink(f.name)

        assert result[0]["version"] == "nginx"

    def test_port_without_service(self):
        xml = NMAP_XML_TEMPLATE.format(ports=_make_port_xml(8080))
        with tempfile.NamedTemporaryFile(mode="w", suffix=".xml", delete=False) as f:
            f.write(xml)
            f.flush()
            result = _parse_nmap_xml(f.name)
            os.unlink(f.name)

        assert result[0]["port"] == 8080
        assert "service" not in result[0]

    def test_port_without_state_element_skipped(self):
        """Port without <state> element → ignored."""
        xml = NMAP_XML_TEMPLATE.format(
            ports='<port protocol="tcp" portid="22"></port>'
        )
        with tempfile.NamedTemporaryFile(mode="w", suffix=".xml", delete=False) as f:
            f.write(xml)
            f.flush()
            result = _parse_nmap_xml(f.name)
            os.unlink(f.name)

        assert len(result) == 0

    def test_invalid_xml_returns_empty(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".xml", delete=False) as f:
            f.write("not xml at all")
            f.flush()
            result = _parse_nmap_xml(f.name)
            os.unlink(f.name)

        assert result == []

    def test_file_not_found_returns_empty(self):
        result = _parse_nmap_xml("/nonexistent/path.xml")
        assert result == []

    def test_empty_host_no_ports(self):
        xml = '<?xml version="1.0"?><nmaprun><host><ports></ports></host></nmaprun>'
        with tempfile.NamedTemporaryFile(mode="w", suffix=".xml", delete=False) as f:
            f.write(xml)
            f.flush()
            result = _parse_nmap_xml(f.name)
            os.unlink(f.name)

        assert result == []

    def test_udp_protocol(self):
        xml = NMAP_XML_TEMPLATE.format(ports=_make_port_xml(53, proto="udp", service="dns"))
        with tempfile.NamedTemporaryFile(mode="w", suffix=".xml", delete=False) as f:
            f.write(xml)
            f.flush()
            result = _parse_nmap_xml(f.name)
            os.unlink(f.name)

        assert result[0]["proto"] == "udp"


# ===================================================================
# _run_nmap
# ===================================================================


class TestRunNmap:
    async def test_successful_run(self):
        mock_proc = AsyncMock()
        mock_proc.wait = AsyncMock(return_value=0)

        ports_data = [{"port": 80, "proto": "tcp", "state": "open", "service": "http"}]

        with (
            patch("asyncio.create_subprocess_exec", return_value=mock_proc),
            patch("app.scanners.ports._parse_nmap_xml", return_value=ports_data),
            patch("os.unlink"),
        ):
            result = await _run_nmap("example.com")

        assert result == ports_data

    async def test_timeout_returns_none(self):
        import asyncio as aio

        mock_proc = AsyncMock()
        mock_proc.wait = AsyncMock(side_effect=aio.TimeoutError())

        with (
            patch("asyncio.create_subprocess_exec", return_value=mock_proc),
            patch("os.unlink"),
        ):
            result = await _run_nmap("example.com")

        assert result is None

    async def test_exception_returns_none(self):
        with (
            patch("asyncio.create_subprocess_exec", side_effect=FileNotFoundError("nmap")),
            patch("os.unlink"),
        ):
            result = await _run_nmap("example.com")

        assert result is None

    async def test_tempfile_cleanup(self):
        mock_proc = AsyncMock()
        mock_proc.wait = AsyncMock(return_value=0)

        with (
            patch("asyncio.create_subprocess_exec", return_value=mock_proc),
            patch("app.scanners.ports._parse_nmap_xml", return_value=[]),
            patch("os.unlink") as mock_unlink,
        ):
            await _run_nmap("example.com")

        mock_unlink.assert_called_once()

    async def test_cleanup_oserror_silenced(self):
        """os.unlink raises OSError in the finally → silenced without crash."""
        mock_proc = AsyncMock()
        mock_proc.wait = AsyncMock(return_value=0)

        with (
            patch("asyncio.create_subprocess_exec", return_value=mock_proc),
            patch("app.scanners.ports._parse_nmap_xml", return_value=[{"port": 80}]),
            patch("os.unlink", side_effect=OSError("Permission denied")),
        ):
            result = await _run_nmap("example.com")

        # The result is returned normally despite the cleanup failure
        assert result == [{"port": 80}]


# ===================================================================
# _whois_sync
# ===================================================================


class FakePywhoisError(Exception):
    """Stand-in for whois.parser.PywhoisError on the mocked module (the
    scanner's except clause needs a real exception class, not a MagicMock)."""


def _mock_whois(mock_w):
    """Create a context manager that injects a mock whois module."""
    import sys
    mock_module = MagicMock()
    mock_module.whois = MagicMock(return_value=mock_w)
    mock_module.parser.PywhoisError = FakePywhoisError
    return patch.dict(sys.modules, {"whois": mock_module})


def _mock_whois_error(exc):
    """Create a context manager that makes whois.whois() fail."""
    import sys
    mock_module = MagicMock()
    mock_module.whois = MagicMock(side_effect=exc)
    mock_module.parser.PywhoisError = FakePywhoisError
    return patch.dict(sys.modules, {"whois": mock_module})


class TestWhoisSync:
    def test_successful_whois(self):
        mock_w = MagicMock()
        mock_w.domain_name = "example.com"
        mock_w.creation_date = datetime(2020, 1, 15)
        mock_w.expiration_date = datetime(2026, 1, 15)
        mock_w.registrar = "Gandi SAS"

        with _mock_whois(mock_w):
            result = _whois_sync("example.com")

        assert result is not None
        assert result["registrar"] == "Gandi SAS"
        assert result["creation_date"] == "2020-01-15"
        assert result["expiration_date"] == "2026-01-15"
        assert isinstance(result["age_days"], int)
        assert result["age_days"] > 0

    def test_creation_date_as_list(self):
        """python-whois sometimes returns a list of dates."""
        mock_w = MagicMock()
        mock_w.domain_name = "example.com"
        mock_w.creation_date = [datetime(2020, 6, 1), datetime(2020, 6, 2)]
        mock_w.expiration_date = [datetime(2025, 6, 1)]
        mock_w.registrar = "OVH"

        with _mock_whois(mock_w):
            result = _whois_sync("example.com")

        assert result is not None
        assert result["creation_date"] == "2020-06-01"
        assert result["expiration_date"] == "2025-06-01"

    def test_no_domain_name_returns_none(self):
        mock_w = MagicMock()
        mock_w.domain_name = None

        with _mock_whois(mock_w):
            result = _whois_sync("unknown.tld")

        assert result is None

    def test_whois_returns_none(self):
        mock_w = None
        with _mock_whois(mock_w):
            result = _whois_sync("unknown.tld")

        assert result is None

    def test_whois_exception_returns_none(self):
        with _mock_whois_error(TimeoutError("timeout")):
            result = _whois_sync("example.com")

        assert result is None

    def test_whois_no_match_returns_none(self):
        """A PywhoisError ("no match for domain") is an expected outcome."""
        with _mock_whois_error(FakePywhoisError("No match for example.com")):
            result = _whois_sync("example.com")

        assert result is None

    def test_import_error_returns_none(self):
        """If python-whois is not installed → None."""
        import builtins
        original_import = builtins.__import__

        def fake_import(name, *args, **kwargs):
            if name == "whois":
                raise ImportError("No module named 'whois'")
            return original_import(name, *args, **kwargs)

        with patch("builtins.__import__", side_effect=fake_import):
            result = _whois_sync("example.com")

        assert result is None

    def test_no_creation_date_age_none(self):
        mock_w = MagicMock()
        mock_w.domain_name = "example.com"
        mock_w.creation_date = None
        mock_w.expiration_date = None
        mock_w.registrar = "Test"

        with _mock_whois(mock_w):
            result = _whois_sync("example.com")

        assert result is not None
        assert result["age_days"] is None

    def test_creation_date_string_no_age(self):
        """creation_date is a string → age_days = None (not isinstance datetime)."""
        mock_w = MagicMock()
        mock_w.domain_name = "example.com"
        mock_w.creation_date = "2020-01-01"
        mock_w.expiration_date = "2026-01-01"
        mock_w.registrar = "Test"

        with _mock_whois(mock_w):
            result = _whois_sync("example.com")

        assert result is not None
        assert result["age_days"] is None
        assert result["creation_date"] == "2020-01-01"


# ===================================================================
# _first_date (internal helper tested via _whois_sync)
# ===================================================================


class TestFirstDateHelper:
    """Dedicated tests for the _first_date helper internal to _whois_sync.

    _first_date handles 3 branches:
      - isinstance(val, list) → takes the first element
      - isinstance(val, datetime) → strftime
      - otherwise → str(val) if val, "" if falsy
    """

    def test_datetime_value(self):
        """datetime → formatted as YYYY-MM-DD."""
        mock_w = MagicMock()
        mock_w.domain_name = "example.com"
        mock_w.creation_date = datetime(2023, 7, 15, 12, 30)
        mock_w.expiration_date = datetime(2028, 7, 15)
        mock_w.registrar = "Test"

        with _mock_whois(mock_w):
            result = _whois_sync("example.com")

        assert result is not None
        assert result["creation_date"] == "2023-07-15"
        assert result["expiration_date"] == "2028-07-15"

    def test_list_of_datetimes(self):
        """List of datetimes → takes the first, formats as YYYY-MM-DD."""
        mock_w = MagicMock()
        mock_w.domain_name = "example.com"
        mock_w.creation_date = [datetime(2020, 3, 10), datetime(2020, 3, 11)]
        mock_w.expiration_date = [datetime(2025, 3, 10)]
        mock_w.registrar = "Test"

        with _mock_whois(mock_w):
            result = _whois_sync("example.com")

        assert result is not None
        assert result["creation_date"] == "2020-03-10"
        assert result["expiration_date"] == "2025-03-10"

    def test_string_value(self):
        """Raw string → passed as is via str(val)."""
        mock_w = MagicMock()
        mock_w.domain_name = "example.com"
        mock_w.creation_date = "before 2000"
        mock_w.expiration_date = "unknown"
        mock_w.registrar = "Test"

        with _mock_whois(mock_w):
            result = _whois_sync("example.com")

        assert result is not None
        assert result["creation_date"] == "before 2000"
        assert result["expiration_date"] == "unknown"

    def test_none_value(self):
        """None → empty string."""
        mock_w = MagicMock()
        mock_w.domain_name = "example.com"
        mock_w.creation_date = None
        mock_w.expiration_date = None
        mock_w.registrar = "Test"

        with _mock_whois(mock_w):
            result = _whois_sync("example.com")

        assert result is not None
        assert result["creation_date"] == ""
        assert result["expiration_date"] == ""

    def test_list_with_none_first(self):
        """List whose first element is None → empty string."""
        mock_w = MagicMock()
        mock_w.domain_name = "example.com"
        mock_w.creation_date = [None, datetime(2020, 1, 1)]
        mock_w.expiration_date = [None]
        mock_w.registrar = "Test"

        with _mock_whois(mock_w):
            result = _whois_sync("example.com")

        assert result is not None
        assert result["creation_date"] == ""
        assert result["expiration_date"] == ""

    def test_list_with_string_first(self):
        """List whose first element is a string → str(val)."""
        mock_w = MagicMock()
        mock_w.domain_name = "example.com"
        mock_w.creation_date = ["2019-05-20", datetime(2019, 5, 20)]
        mock_w.expiration_date = ["N/A"]
        mock_w.registrar = "Test"

        with _mock_whois(mock_w):
            result = _whois_sync("example.com")

        assert result is not None
        assert result["creation_date"] == "2019-05-20"
        assert result["expiration_date"] == "N/A"


# ===================================================================
# _check_whois
# ===================================================================


class TestCheckWhois:
    async def test_whois_info_finding(self):
        info = {
            "registrar": "Gandi SAS",
            "creation_date": "2020-01-15",
            "expiration_date": "2026-01-15",
            "age_days": 2000,
        }
        findings = []
        with patch("app.scanners.ports._whois_sync", return_value=info):
            await _check_whois("example.com", findings)

        info_findings = [f for f in findings if f.severity == "info"]
        assert len(info_findings) == 1
        assert "WHOIS" in info_findings[0].title
        assert "Gandi" in info_findings[0].description

    async def test_young_domain_warning(self):
        info = {
            "registrar": "NameCheap",
            "creation_date": "2026-03-01",
            "expiration_date": "2027-03-01",
            "age_days": 10,
        }
        findings = []
        with patch("app.scanners.ports._whois_sync", return_value=info):
            await _check_whois("new-domain.com", findings)

        medium_findings = [f for f in findings if f.severity == "medium"]
        assert len(medium_findings) == 1
        assert "recent" in medium_findings[0].title.lower()
        assert "10 days" in medium_findings[0].title

    async def test_old_domain_no_warning(self):
        info = {
            "registrar": "Gandi",
            "creation_date": "2015-01-01",
            "expiration_date": "2026-01-01",
            "age_days": 4000,
        }
        findings = []
        with patch("app.scanners.ports._whois_sync", return_value=info):
            await _check_whois("example.com", findings)

        medium_findings = [f for f in findings if f.severity == "medium"]
        assert len(medium_findings) == 0

    async def test_whois_returns_none(self):
        findings = []
        with patch("app.scanners.ports._whois_sync", return_value=None):
            await _check_whois("example.com", findings)

        assert len(findings) == 0

    async def test_whois_exception_silenced(self):
        findings = []
        with patch("app.scanners.ports._whois_sync", side_effect=TimeoutError("timeout")):
            await _check_whois("example.com", findings)

        assert len(findings) == 0

    async def test_whois_no_details_no_info_finding(self):
        """WHOIS without registrar/dates → no info finding.

        Verify that empty strings are treated as falsy by
        info.get("registrar") etc. — no detail is added.
        """
        info = {
            "registrar": "",
            "creation_date": "",
            "expiration_date": "",
            "age_days": None,
        }
        findings = []
        with patch("app.scanners.ports._whois_sync", return_value=info):
            await _check_whois("example.com", findings)

        # No info finding (empty strings = falsy)
        assert len(findings) == 0

    async def test_whois_partial_details(self):
        """WHOIS with registrar but without dates → one info finding with registrar only."""
        info = {
            "registrar": "Gandi SAS",
            "creation_date": "",
            "expiration_date": "",
            "age_days": None,
        }
        findings = []
        with patch("app.scanners.ports._whois_sync", return_value=info):
            await _check_whois("example.com", findings)

        info_findings = [f for f in findings if f.severity == "info"]
        assert len(info_findings) == 1
        assert "Gandi" in info_findings[0].description
        # Empty dates are not included in the description
        assert "Created on" not in info_findings[0].description
        assert "Expires on" not in info_findings[0].description

    async def test_whois_age_none_no_medium(self):
        """age_days None → no medium finding."""
        info = {
            "registrar": "Gandi",
            "creation_date": "2020-01-01",
            "expiration_date": "",
            "age_days": None,
        }
        findings = []
        with patch("app.scanners.ports._whois_sync", return_value=info):
            await _check_whois("example.com", findings)

        medium_findings = [f for f in findings if f.severity == "medium"]
        assert len(medium_findings) == 0


# ===================================================================
# PortsScanner.scan — full scan
# ===================================================================


class TestPortsScannerScan:
    async def test_nmap_not_available_whois_only(self, scanner):
        """nmap absent → only WHOIS is run."""
        whois_info = {"registrar": "Test", "creation_date": "2020-01-01",
                      "expiration_date": "2026-01-01", "age_days": 2000}
        with (
            patch("app.scanners.ports.is_available", return_value=False),
            patch("app.scanners.ports._whois_sync", return_value=whois_info),
        ):
            result = await scanner.scan("example.com")

        assert any("WHOIS" in f.title for f in result.findings)
        # info only → score = 100
        assert result.score == 100

    async def test_dangerous_port_detected(self, scanner):
        """Dangerous port open → high finding."""
        ports = [{"port": 3306, "proto": "tcp", "state": "open", "service": "mysql"}]
        with (
            patch("app.scanners.ports.is_available", return_value=True),
            patch("app.scanners.ports._run_nmap", new_callable=AsyncMock, return_value=ports),
            patch("app.scanners.ports._whois_sync", return_value=None),
        ):
            result = await scanner.scan("example.com")

        high_findings = [f for f in result.findings if f.severity == "high"]
        assert len(high_findings) == 1
        assert "3306" in high_findings[0].title
        assert "mysql" in high_findings[0].title.lower()
        # 1 high (-20) → score = 80
        assert result.score == 80

    async def test_multiple_dangerous_ports(self, scanner):
        """Several dangerous ports → one finding per port."""
        ports = [
            {"port": 21, "proto": "tcp", "state": "open", "service": "ftp"},
            {"port": 23, "proto": "tcp", "state": "open", "service": "telnet"},
            {"port": 3389, "proto": "tcp", "state": "open", "service": "ms-wbt-server"},
        ]
        with (
            patch("app.scanners.ports.is_available", return_value=True),
            patch("app.scanners.ports._run_nmap", new_callable=AsyncMock, return_value=ports),
            patch("app.scanners.ports._whois_sync", return_value=None),
        ):
            result = await scanner.scan("example.com")

        high_findings = [f for f in result.findings if f.severity == "high"]
        assert len(high_findings) == 3
        # 3 high (-60) → score = 40
        assert result.score == 40

    async def test_non_standard_port_info_finding(self, scanner):
        """Non-standard port open (neither 80/443 nor dangerous) → info finding."""
        ports = [
            {"port": 80, "proto": "tcp", "state": "open", "service": "http"},
            {"port": 8080, "proto": "tcp", "state": "open", "service": "http-proxy"},
        ]
        with (
            patch("app.scanners.ports.is_available", return_value=True),
            patch("app.scanners.ports._run_nmap", new_callable=AsyncMock, return_value=ports),
            patch("app.scanners.ports._whois_sync", return_value=None),
        ):
            result = await scanner.scan("example.com")

        info_findings = [f for f in result.findings if f.severity == "info"]
        assert len(info_findings) == 1
        assert "8080" in info_findings[0].description

    async def test_only_standard_ports_no_info(self, scanner):
        """Only 80 and 443 open → no info finding (nothing non-standard)."""
        ports = [
            {"port": 80, "proto": "tcp", "state": "open", "service": "http"},
            {"port": 443, "proto": "tcp", "state": "open", "service": "https"},
        ]
        with (
            patch("app.scanners.ports.is_available", return_value=True),
            patch("app.scanners.ports._run_nmap", new_callable=AsyncMock, return_value=ports),
            patch("app.scanners.ports._whois_sync", return_value=None),
        ):
            result = await scanner.scan("example.com")

        assert len(result.findings) == 0
        # No finding → perfect score
        assert result.score == 100

    async def test_nmap_returns_none(self, scanner):
        """nmap fails (timeout) → no port findings."""
        with (
            patch("app.scanners.ports.is_available", return_value=True),
            patch("app.scanners.ports._run_nmap", new_callable=AsyncMock, return_value=None),
            patch("app.scanners.ports._whois_sync", return_value=None),
        ):
            result = await scanner.scan("example.com")

        assert len(result.findings) == 0
        assert result.score == 100

    async def test_no_open_ports(self, scanner):
        """No port open → no findings."""
        ports = [
            {"port": 80, "proto": "tcp", "state": "filtered"},
            {"port": 443, "proto": "tcp", "state": "closed"},
        ]
        with (
            patch("app.scanners.ports.is_available", return_value=True),
            patch("app.scanners.ports._run_nmap", new_callable=AsyncMock, return_value=ports),
            patch("app.scanners.ports._whois_sync", return_value=None),
        ):
            result = await scanner.scan("example.com")

        assert len(result.findings) == 0
        assert result.score == 100

    async def test_young_domain_score(self, scanner):
        """Recent domain (medium) → score = 90."""
        whois_info = {"registrar": "Test", "creation_date": "2026-03-01",
                      "expiration_date": "2027-03-01", "age_days": 10}
        with (
            patch("app.scanners.ports.is_available", return_value=False),
            patch("app.scanners.ports._whois_sync", return_value=whois_info),
        ):
            result = await scanner.scan("new-domain.com")

        # 1 info (0) + 1 medium (-10) → score = 90
        assert result.score == 90

    async def test_dangerous_port_with_raw_data(self, scanner):
        """The finding of a dangerous port includes JSON raw_data."""
        ports = [{"port": 6379, "proto": "tcp", "state": "open", "service": "redis"}]
        with (
            patch("app.scanners.ports.is_available", return_value=True),
            patch("app.scanners.ports._run_nmap", new_callable=AsyncMock, return_value=ports),
            patch("app.scanners.ports._whois_sync", return_value=None),
        ):
            result = await scanner.scan("example.com")

        high = [f for f in result.findings if f.severity == "high"]
        assert len(high) == 1
        raw = json.loads(high[0].raw_data)
        assert raw["port"] == 6379

    async def test_whois_and_nmap_parallel(self, scanner):
        """WHOIS and nmap run in parallel — both results are present."""
        ports = [{"port": 3306, "proto": "tcp", "state": "open", "service": "mysql"}]
        whois_info = {"registrar": "Gandi", "creation_date": "2020-01-01",
                      "expiration_date": "2026-01-01", "age_days": 2000}
        with (
            patch("app.scanners.ports.is_available", return_value=True),
            patch("app.scanners.ports._run_nmap", new_callable=AsyncMock, return_value=ports),
            patch("app.scanners.ports._whois_sync", return_value=whois_info),
        ):
            result = await scanner.scan("example.com")

        assert any("WHOIS" in f.title for f in result.findings)
        assert any("3306" in f.title for f in result.findings)
        # 1 high (-20) + 1 info (0) → score = 80
        assert result.score == 80

    @pytest.mark.parametrize("port,service", list(DANGEROUS_PORTS.items()))
    async def test_each_dangerous_port(self, scanner, port, service):
        """Each port in DANGEROUS_PORTS produces a high finding."""
        ports = [{"port": port, "proto": "tcp", "state": "open", "service": service.lower()}]
        with (
            patch("app.scanners.ports.is_available", return_value=True),
            patch("app.scanners.ports._run_nmap", new_callable=AsyncMock, return_value=ports),
            patch("app.scanners.ports._whois_sync", return_value=None),
        ):
            result = await scanner.scan("example.com")

        high = [f for f in result.findings if f.severity == "high"]
        assert len(high) == 1
        assert str(port) in high[0].title

    async def test_scanner_name_and_weight(self, scanner):
        assert scanner.name == "ports"
        assert scanner.weight == 0.10
