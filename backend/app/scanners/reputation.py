import os
import socket
import httpx

from app.scanners.base import BaseScanner, ScanResult, FindingData

ABUSEIPDB_URL = "https://api.abuseipdb.com/api/v2/check"
SPAMHAUS_ZEN = "zen.spamhaus.org"


class ReputationScanner(BaseScanner):
    name = "reputation"
    weight = 0.15

    async def scan(self, domain: str) -> ScanResult:
        findings: list[FindingData] = []

        ips = _resolve_ips(domain)
        if not ips:
            findings.append(FindingData(
                severity="info",
                title="Unable to resolve the domain's IPs",
                description=f"No IP resolved for {domain}.",
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
                    title=f"IP {ip}: abuse score {score}/100",
                    description=f"{reports} report(s) in the last 90 days (AbuseIPDB).",
                    remediation="Contact the hosting provider or consider changing the IP.",
                ))
            except Exception:
                continue


def _check_spamhaus_dns(ips: list[str], findings: list) -> None:
    for ip in ips:
        if ":" in ip:
            continue  # IPv6 not supported by Spamhaus ZEN via simple lookup
        reversed_ip = ".".join(reversed(ip.split(".")))
        query = f"{reversed_ip}.{SPAMHAUS_ZEN}"
        try:
            socket.gethostbyname(query)
            # If resolved → IP is listed
            findings.append(FindingData(
                severity="high",
                title=f"IP {ip} listed in Spamhaus ZEN",
                description="The IP is present in Spamhaus blocklists (spam, malware, or compromise).",
                remediation="Check the IP at https://check.spamhaus.org and request removal if legitimate.",
            ))
        except socket.gaierror:
            pass  # NXDOMAIN = not in the list, which is good
