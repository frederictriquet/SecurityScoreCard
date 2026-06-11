import base64
import os
import socket
import httpx

import dns.resolver
import dns.asyncresolver

from app.scanners.base import BaseScanner, ScanResult, FindingData

ABUSEIPDB_URL = "https://api.abuseipdb.com/api/v2/check"
SPAMHAUS_ZEN = "zen.spamhaus.org"
PHISHTANK_URL = "https://checkurl.phishtank.com/checkurl/"

# Domain-based DNSBLs (queried with the registrable domain, unlike Spamhaus ZEN
# which is IP-based). A 127.0.0.x answer means listed; the last octet is a
# bitmask identifying the sub-list(s) the domain hit.
SURBL_BITS = {
    8: "phishing",
    16: "malware",
    64: "abuse",
    128: "cracked",
}
URIBL_BITS = {
    2: "black",
    4: "grey",
    8: "red",
}
DOMAIN_DNSBLS = [
    {"name": "SURBL", "zone": "multi.surbl.org", "bits": SURBL_BITS, "site": "https://surbl.org"},
    {"name": "URIBL", "zone": "multi.uribl.com", "bits": URIBL_BITS, "site": "https://uribl.com"},
]

# Second-level public suffixes used by the registrable-domain heuristic. Not an
# exhaustive Public Suffix List (no extra dependency), just the common cases so
# that e.g. "mail.example.co.uk" is queried as "example.co.uk".
MULTI_PART_TLDS = {
    "co.uk", "org.uk", "gov.uk", "ac.uk", "me.uk", "ltd.uk", "plc.uk",
    "com.au", "net.au", "org.au", "gov.au", "edu.au", "id.au",
    "co.nz", "net.nz", "org.nz",
    "co.za", "org.za",
    "co.jp", "ne.jp", "or.jp", "go.jp",
    "com.br", "com.mx", "com.cn", "com.tr", "com.sg", "com.hk", "com.tw",
    "co.in", "co.kr", "co.il", "co.id", "co.th",
}


class ReputationScanner(BaseScanner):
    name = "reputation"
    weight = 0.15

    async def scan(self, domain: str) -> ScanResult:
        findings: list[FindingData] = []

        # SURBL/URIBL and PhishTank are domain-based and independent of the
        # resolved IP, so run them up front regardless of whether the domain
        # resolves to an IP.
        await _check_surbl_uribl(domain, findings)
        await _check_phishtank(domain, findings)

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


def _registrable_domain(domain: str) -> str:
    """Best-effort registrable (base) domain for DNSBL queries.

    Strips arbitrary subdomains so SURBL/URIBL are queried with the domain that
    actually matters (e.g. ``mail.example.co.uk`` -> ``example.co.uk``). Uses a
    small list of two-level public suffixes rather than a full PSL dependency.
    """
    labels = domain.strip(".").lower().split(".")
    if len(labels) <= 2:
        return ".".join(labels)
    if ".".join(labels[-2:]) in MULTI_PART_TLDS:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


async def _query_dnsbl(
    resolver: dns.asyncresolver.Resolver, fqdn: str
) -> list[str] | None:
    """Resolve a DNSBL query.

    Returns the list of A answers (empty list when the domain is not listed,
    i.e. NXDOMAIN/NoAnswer) or ``None`` when the lookup could not be performed
    (timeout, network/DNS error) so the caller can treat it as undetermined.
    """
    try:
        answers = await resolver.resolve(fqdn, "A")
        return [str(r) for r in answers]
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        return []  # not listed
    except Exception:
        return None  # timeout / DNS error -> undetermined


def _decode_dnsbl(responses: list[str], bits: dict[int, str]) -> tuple[bool, list[str], bool]:
    """Classify DNSBL A answers.

    Returns ``(listed, sublists, refused)`` where ``refused`` flags the special
    127.0.0.1 code used by URIBL to signal a query refused / rate-limited /
    blocked response (typical on shared public resolvers) — which must NOT be
    counted as a listing.
    """
    listed = False
    refused = False
    sublists: set[str] = set()
    for addr in responses:
        if not addr.startswith("127.0.0."):
            continue  # only loopback codes are valid DNSBL responses
        last_octet = int(addr.rsplit(".", 1)[1])
        if last_octet == 1:
            refused = True
            continue
        listed = True
        for bit, label in bits.items():
            if last_octet & bit:
                sublists.add(label)
    return listed, sorted(sublists), refused


async def _check_surbl_uribl(domain: str, findings: list[FindingData]) -> None:
    registrable = _registrable_domain(domain)
    # Use the system/default resolver (from /etc/resolv.conf). SURBL and URIBL
    # block queries coming from large public/open resolvers (e.g. Google,
    # Cloudflare) by policy — URIBL answers them with the 127.0.0.1
    # query-refused code and SURBL withholds its data — so forcing public DNS
    # would make real listings essentially undetectable. This mirrors the
    # IP-based Spamhaus check, which relies on the system resolver too.
    resolver = dns.asyncresolver.Resolver()

    listed_on: list[tuple[str, list[str]]] = []
    undetermined: list[str] = []

    for entry in DOMAIN_DNSBLS:
        fqdn = f"{registrable}.{entry['zone']}"
        responses = await _query_dnsbl(resolver, fqdn)
        if responses is None:
            continue  # lookup failed, skip silently
        listed, sublists, refused = _decode_dnsbl(responses, entry["bits"])
        if listed:
            listed_on.append((entry["name"], sublists))
        elif refused:
            undetermined.append(entry["name"])

    if listed_on:
        details = []
        for name, sublists in listed_on:
            details.append(f"{name} ({', '.join(sublists)})" if sublists else name)
        findings.append(FindingData(
            severity="medium",
            title=f"Domain listed on {' / '.join(name for name, _ in listed_on)}",
            description=(
                f"The registrable domain {registrable} is listed on the following "
                f"domain-based blocklists: {'; '.join(details)}. These DNSBLs flag "
                "domains seen in spam, phishing, or malware campaigns."
            ),
            remediation=(
                "Verify that the domain is not compromised or being abused. If you "
                "believe this is a false positive, request delisting at "
                "https://surbl.org and/or https://uribl.com."
            ),
        ))
    elif undetermined:
        findings.append(FindingData(
            severity="info",
            title="Domain reputation undetermined (SURBL / URIBL)",
            description=(
                f"{', '.join(undetermined)} returned a query-refused code "
                "(127.0.0.1), usually caused by rate limiting on shared public "
                "resolvers. The listing status could not be determined."
            ),
        ))


def _phishtank_true(value) -> bool:
    """Interpret a PhishTank boolean field, which the API may serialize as a
    JSON bool or as a string ("true"/"yes")."""
    if value is True:
        return True
    return isinstance(value, str) and value.lower() in ("true", "yes", "y")


async def _check_phishtank(domain: str, findings: list[FindingData]) -> None:
    """Check the registrable domain against the PhishTank database.

    The API key is optional (PHISHTANK_API_KEY): PhishTank answers unkeyed
    requests too, just with a lower rate limit. Only a positive, verified and
    still-valid phishing match yields a finding — any error (network, timeout,
    non-200 including rate limiting, unparseable body) or a "not in database"
    answer is indeterminate and must never degrade the score.
    """
    url = f"http://{_registrable_domain(domain)}/"
    data = {
        # PhishTank expects the checked URL base64-encoded
        "url": base64.b64encode(url.encode()).decode(),
        "format": "json",
    }
    app_key = os.getenv("PHISHTANK_API_KEY", "")
    if app_key:
        data["app_key"] = app_key

    try:
        async with httpx.AsyncClient(timeout=10) as client:
            resp = await client.post(PHISHTANK_URL, data=data)
        if resp.status_code != 200:
            return  # rate-limited (429/509) or server error -> indeterminate
        results = resp.json().get("results", {})
    except Exception:
        return  # network error / timeout / unparseable body -> indeterminate

    if not (
        _phishtank_true(results.get("in_database"))
        and _phishtank_true(results.get("valid"))
        and _phishtank_true(results.get("verified"))
    ):
        return  # not listed, retracted, or unverified entry -> no finding

    description = (
        f"PhishTank lists {url} as a verified and still-active phishing site."
    )
    detail_page = results.get("phish_detail_page")
    if detail_page:
        description += f" Details: {detail_page}"
    findings.append(FindingData(
        severity="medium",
        title="Domain listed on PhishTank as phishing",
        description=description,
        remediation=(
            "Check whether the site is compromised or hosting phishing content, "
            "clean it up, then request delisting on the phish detail page at "
            "https://phishtank.org."
        ),
    ))
