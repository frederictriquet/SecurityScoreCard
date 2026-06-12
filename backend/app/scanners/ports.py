"""Port scanner via nmap — unprivileged connect scan."""

import asyncio
import json
import logging
import os
import tempfile
import xml.etree.ElementTree as ET

from app.scanners.base import BaseScanner, ScanResult, FindingData

logger = logging.getLogger(__name__)

NMAP_PATH = os.environ.get("NMAP_PATH", "/usr/bin/nmap")
TIMEOUT = 120  # max seconds for the scan

# Ports considered dangerous if exposed on the Internet
DANGEROUS_PORTS = {
    21: "FTP",
    23: "Telnet",
    135: "MS-RPC",
    139: "NetBIOS",
    445: "SMB",
    1433: "MS-SQL",
    1434: "MS-SQL Browser",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    5900: "VNC",
    6379: "Redis",
    11211: "Memcached",
    27017: "MongoDB",
}


def is_available() -> bool:
    return os.path.isfile(NMAP_PATH) and os.access(NMAP_PATH, os.X_OK)


class PortsScanner(BaseScanner):
    name = "ports"
    weight = 0.10

    async def scan(self, domain: str) -> ScanResult:
        findings: list[FindingData] = []

        # WHOIS in parallel with nmap (does not require nmap)
        whois_task = _check_whois(domain, findings)

        if not is_available():
            await whois_task
            return ScanResult.from_findings(findings)

        nmap_task = _run_nmap(domain)
        _, ports = await asyncio.gather(whois_task, nmap_task)
        if ports is None:
            return ScanResult.from_findings(findings)

        open_ports = [p for p in ports if p["state"] == "open"]

        if not open_ports:
            return ScanResult.from_findings(findings)

        # Exposed dangerous ports
        for port_info in open_ports:
            port_num = port_info["port"]
            if port_num in DANGEROUS_PORTS:
                svc_name = port_info.get("service", DANGEROUS_PORTS[port_num])
                findings.append(FindingData(
                    severity="high",
                    title=f"Dangerous port exposed: {port_num}/{port_info['proto']} ({svc_name})",
                    description=f"Port {port_num} ({DANGEROUS_PORTS[port_num]}) is open on the Internet. "
                                "This service should not be directly accessible.",
                    remediation=f"Restrict access to port {port_num} via a firewall or a VPN.",
                    raw_data=json.dumps(port_info),
                ))

        # Summary of open ports (info)
        non_standard = [
            p for p in open_ports
            if p["port"] not in (80, 443) and p["port"] not in DANGEROUS_PORTS
        ]
        if non_standard:
            port_list = ", ".join(
                f"{p['port']}/{p['proto']} ({p.get('service', '?')})"
                for p in non_standard[:15]
            )
            findings.append(FindingData(
                severity="info",
                title=f"{len(open_ports)} open port(s) detected",
                description=f"Non-standard open ports: {port_list}",
                remediation="Check that only the necessary ports are exposed.",
            ))

        return ScanResult.from_findings(findings)


async def _run_nmap(domain: str) -> list[dict] | None:
    """Runs nmap and returns the list of detected ports."""
    with tempfile.NamedTemporaryFile(suffix=".xml", delete=False) as tmp:
        xml_path = tmp.name

    try:
        proc = await asyncio.create_subprocess_exec(
            NMAP_PATH,
            "-sT",              # connect scan (no root required)
            "--top-ports", "100",
            "-T4",              # aggressive but reasonable timing
            "-sV",              # version detection
            "--version-light",  # fast version detection (level 2)
            "-oX", xml_path,    # XML output
            "--open",           # only show open ports
            domain,
            stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.DEVNULL,
        )
        await asyncio.wait_for(proc.wait(), timeout=TIMEOUT)

        return _parse_nmap_xml(xml_path)

    except (asyncio.TimeoutError, OSError) as exc:
        logger.warning("ports: nmap scan failed for %s: %s", domain, exc)
        return None
    finally:
        try:
            os.unlink(xml_path)
        except OSError:
            pass


def _parse_nmap_xml(xml_path: str) -> list[dict]:
    """Parses the XML output of nmap."""
    ports: list[dict] = []
    try:
        tree = ET.parse(xml_path)
        root = tree.getroot()

        for host in root.findall(".//host"):
            for port_el in host.findall(".//port"):
                state_el = port_el.find("state")
                service_el = port_el.find("service")

                if state_el is None:
                    continue

                port_data = {
                    "port": int(port_el.get("portid", "0")),
                    "proto": port_el.get("protocol", "tcp"),
                    "state": state_el.get("state", ""),
                }

                if service_el is not None:
                    svc_name = service_el.get("name", "")
                    svc_product = service_el.get("product", "")
                    svc_version = service_el.get("version", "")
                    port_data["service"] = svc_name
                    if svc_product:
                        version_str = f"{svc_product}"
                        if svc_version:
                            version_str += f" {svc_version}"
                        port_data["version"] = version_str

                ports.append(port_data)

    except (ET.ParseError, FileNotFoundError) as exc:
        logger.warning("ports: could not parse nmap XML output: %s", exc)

    return ports


async def _check_whois(domain: str, findings: list[FindingData]) -> None:
    """Retrieves WHOIS info and flags recently created domains."""
    loop = asyncio.get_event_loop()
    try:
        info = await asyncio.wait_for(
            loop.run_in_executor(None, _whois_sync, domain),
            timeout=15,
        )
        if info is None:
            return

        details: list[str] = []
        if info.get("registrar"):
            details.append(f"Registrar: {info['registrar']}")
        if info.get("creation_date"):
            details.append(f"Created on: {info['creation_date']}")
        if info.get("expiration_date"):
            details.append(f"Expires on: {info['expiration_date']}")

        if details:
            findings.append(FindingData(
                severity="info",
                title="Domain WHOIS information",
                description=" | ".join(details),
                raw_data=json.dumps(info),
            ))

        # Domain created less than 30 days ago = suspicious
        if info.get("age_days") is not None and info["age_days"] < 30:
            findings.append(FindingData(
                severity="medium",
                title=f"Very recent domain ({info['age_days']} days)",
                description="The domain was registered less than 30 days ago. "
                            "Recent domains are often associated with phishing or spam.",
                remediation="Check the legitimacy of the domain.",
            ))

    except (asyncio.TimeoutError, OSError) as exc:
        logger.debug("ports: WHOIS lookup failed for %s: %s", domain, exc)


def _whois_sync(domain: str) -> dict | None:
    """Blocking WHOIS query (to be run in an executor)."""
    try:
        import whois
    except ImportError:
        logger.debug("ports: whois library not installed, skipping WHOIS for %s", domain)
        return None

    try:
        w = whois.whois(domain)
        if not w or not w.domain_name:
            return None

        from datetime import datetime

        def _first_date(val) -> str:
            if isinstance(val, list):
                val = val[0]
            if isinstance(val, datetime):
                return val.strftime("%Y-%m-%d")
            return str(val) if val else ""

        creation = _first_date(w.creation_date)
        expiration = _first_date(w.expiration_date)
        registrar = w.registrar or ""

        age_days = None
        if w.creation_date:
            cd = w.creation_date[0] if isinstance(w.creation_date, list) else w.creation_date
            if isinstance(cd, datetime):
                age_days = (datetime.now() - cd).days

        return {
            "registrar": registrar,
            "creation_date": creation,
            "expiration_date": expiration,
            "age_days": age_days,
        }
    except (whois.parser.PywhoisError, OSError, ValueError) as exc:
        # PywhoisError covers "no match" answers; OSError the network layer.
        logger.debug("ports: WHOIS query failed for %s: %s", domain, exc)
        return None
