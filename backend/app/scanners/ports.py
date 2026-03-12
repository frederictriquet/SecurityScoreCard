"""Scanner de ports via nmap — connect scan non-privilégié."""

import asyncio
import json
import os
import tempfile
import xml.etree.ElementTree as ET

from app.scanners.base import BaseScanner, ScanResult, FindingData

NMAP_PATH = os.environ.get("NMAP_PATH", "/usr/bin/nmap")
TIMEOUT = 120  # secondes max pour le scan

# Ports considérés comme dangereux s'ils sont exposés sur Internet
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

        # WHOIS en parallèle avec nmap (pas besoin de nmap)
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

        # Ports dangereux exposés
        for port_info in open_ports:
            port_num = port_info["port"]
            if port_num in DANGEROUS_PORTS:
                svc_name = port_info.get("service", DANGEROUS_PORTS[port_num])
                findings.append(FindingData(
                    severity="high",
                    title=f"Port dangereux exposé : {port_num}/{port_info['proto']} ({svc_name})",
                    description=f"Le port {port_num} ({DANGEROUS_PORTS[port_num]}) est ouvert sur Internet. "
                                "Ce service ne devrait pas être directement accessible.",
                    remediation=f"Restreindre l'accès au port {port_num} via un pare-feu ou un VPN.",
                    raw_data=json.dumps(port_info),
                ))

        # Résumé des ports ouverts (info)
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
                title=f"{len(open_ports)} port(s) ouvert(s) détecté(s)",
                description=f"Ports non-standard ouverts : {port_list}",
                remediation="Vérifier que seuls les ports nécessaires sont exposés.",
            ))

        return ScanResult.from_findings(findings)


async def _run_nmap(domain: str) -> list[dict] | None:
    """Exécute nmap et retourne la liste des ports détectés."""
    with tempfile.NamedTemporaryFile(suffix=".xml", delete=False) as tmp:
        xml_path = tmp.name

    try:
        proc = await asyncio.create_subprocess_exec(
            NMAP_PATH,
            "-sT",              # connect scan (pas besoin de root)
            "--top-ports", "100",
            "-T4",              # timing agressif mais raisonnable
            "-sV",              # détection de version
            "--version-light",  # version rapide (niveau 2)
            "-oX", xml_path,    # sortie XML
            "--open",           # ne montrer que les ports ouverts
            domain,
            stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.DEVNULL,
        )
        await asyncio.wait_for(proc.wait(), timeout=TIMEOUT)

        return _parse_nmap_xml(xml_path)

    except asyncio.TimeoutError:
        return None
    except Exception:
        return None
    finally:
        try:
            os.unlink(xml_path)
        except OSError:
            pass


def _parse_nmap_xml(xml_path: str) -> list[dict]:
    """Parse la sortie XML de nmap."""
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

    except (ET.ParseError, FileNotFoundError):
        pass

    return ports


async def _check_whois(domain: str, findings: list[FindingData]) -> None:
    """Récupère les infos WHOIS et signale les domaines récemment créés."""
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
            details.append(f"Registrar : {info['registrar']}")
        if info.get("creation_date"):
            details.append(f"Créé le : {info['creation_date']}")
        if info.get("expiration_date"):
            details.append(f"Expire le : {info['expiration_date']}")

        if details:
            findings.append(FindingData(
                severity="info",
                title="Informations WHOIS du domaine",
                description=" | ".join(details),
                raw_data=json.dumps(info),
            ))

        # Domaine créé il y a moins de 30 jours = suspect
        if info.get("age_days") is not None and info["age_days"] < 30:
            findings.append(FindingData(
                severity="medium",
                title=f"Domaine très récent ({info['age_days']} jours)",
                description="Le domaine a été enregistré il y a moins de 30 jours. "
                            "Les domaines récents sont souvent associés à du phishing ou du spam.",
                remediation="Vérifier la légitimité du domaine.",
            ))

    except Exception:
        pass


def _whois_sync(domain: str) -> dict | None:
    """Requête WHOIS bloquante (à exécuter dans un executor)."""
    try:
        import whois
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
    except Exception:
        return None
