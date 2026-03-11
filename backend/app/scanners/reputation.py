import os
import socket
import httpx

from app.scanners.base import BaseScanner, ScanResult, FindingData

ABUSEIPDB_URL = "https://api.abuseipdb.com/api/v2/check"
SPAMHAUS_ZEN = "zen.spamhaus.org"


class ReputationScanner(BaseScanner):
    name = "reputation"
    weight = 0.20

    async def scan(self, domain: str) -> ScanResult:
        findings: list[FindingData] = []

        ips = _resolve_ips(domain)
        if not ips:
            findings.append(FindingData(
                severity="info",
                title="Impossible de résoudre les IPs du domaine",
                description=f"Aucune IP résolue pour {domain}.",
            ))
            return ScanResult.from_findings(findings)

        api_key = os.getenv("ABUSEIPDB_API_KEY", "")
        if api_key:
            await _check_abuseipdb(ips, api_key, findings)
        else:
            _check_spamhaus_dns(ips, findings)

        return ScanResult.from_findings(findings)


def _resolve_ips(domain: str) -> list[str]:
    try:
        results = socket.getaddrinfo(domain, None)
        return [str(r[4][0]) for r in results]
    except Exception:
        return []


async def _check_abuseipdb(ips: list[str], api_key: str, findings: list) -> None:
    headers = {"Key": api_key, "Accept": "application/json"}
    async with httpx.AsyncClient(timeout=10) as client:
        for ip in ips:
            try:
                resp = await client.get(
                    ABUSEIPDB_URL,
                    params={"ipAddress": ip, "maxAgeInDays": 90},
                    headers=headers,
                )
                data = resp.json().get("data", {})
                score = data.get("abuseConfidenceScore", 0)
                reports = data.get("totalReports", 0)

                if score > 80:
                    sev = "critical"
                elif score > 50:
                    sev = "high"
                elif score > 20:
                    sev = "medium"
                elif score > 5:
                    sev = "low"
                else:
                    continue

                findings.append(FindingData(
                    severity=sev,
                    title=f"IP {ip} : score d'abus {score}/100",
                    description=f"{reports} signalement(s) dans les 90 derniers jours (AbuseIPDB).",
                    remediation="Contacter l'hébergeur ou envisager un changement d'IP.",
                ))
            except Exception:
                continue


def _check_spamhaus_dns(ips: list[str], findings: list) -> None:
    for ip in ips:
        if ":" in ip:
            continue  # IPv6 non supporté par Spamhaus ZEN via lookup simple
        reversed_ip = ".".join(reversed(ip.split(".")))
        query = f"{reversed_ip}.{SPAMHAUS_ZEN}"
        try:
            socket.gethostbyname(query)
            # Si résolu → IP listée
            findings.append(FindingData(
                severity="high",
                title=f"IP {ip} référencée dans Spamhaus ZEN",
                description="L'IP est présente dans les listes noires Spamhaus (spam, malware ou compromission).",
                remediation="Vérifier l'IP sur https://check.spamhaus.org et demander une suppression si légitime.",
            ))
        except socket.gaierror:
            pass  # NXDOMAIN = pas dans la liste, c'est bien
