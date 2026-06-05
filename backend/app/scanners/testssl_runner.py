"""Async wrapper for testssl.sh — runs the vulnerability + server-defaults checks."""

import asyncio
import json
import os
import tempfile

from app.scanners.base import FindingData

TESTSSL_PATH = os.environ.get("TESTSSL_PATH", "/opt/testssl/testssl.sh")
TIMEOUT = 120  # max seconds for a full run

# ---------- Severity mapping testssl → our model ----------

_SEVERITY_MAP = {
    "CRITICAL": "critical",
    "HIGH": "high",
    "MEDIUM": "medium",
    "LOW": "low",
    "WARN": "medium",
}

# ---------- Known TLS vulnerabilities ----------

_VULN_CHECKS: dict[str, dict] = {
    "heartbleed": {
        "title": "Heartbleed (CVE-2014-0160)",
        "description": "The server is vulnerable to Heartbleed, allowing the server's memory to be read.",
        "remediation": "Update OpenSSL and regenerate the certificates and private keys.",
    },
    "CCS": {
        "title": "CCS Injection (CVE-2014-0224)",
        "description": "CCS injection vulnerability allowing a man-in-the-middle.",
        "remediation": "Update OpenSSL.",
    },
    "ticketbleed": {
        "title": "Ticketbleed (CVE-2016-9244)",
        "description": "Memory leak via TLS session tickets (F5 BIG-IP).",
        "remediation": "Update the F5 BIG-IP firmware.",
    },
    "ROBOT": {
        "title": "ROBOT (Return Of Bleichenbacher's Oracle Threat)",
        "description": "RSA PKCS#1 v1.5 padding oracle, allowing passive decryption of traffic.",
        "remediation": "Disable RSA key exchange or update the TLS server.",
    },
    "secure_renego": {
        "title": "Insecure TLS renegotiation (CVE-2009-3555)",
        "description": "The server supports insecure renegotiation, vulnerable to prefix injection.",
        "remediation": "Enable secure renegotiation (RFC 5746).",
    },
    "CRIME_TLS": {
        "title": "CRIME (TLS compression enabled)",
        "description": "TLS compression is enabled, allowing secrets to be leaked via compression ratios.",
        "remediation": "Disable TLS compression.",
    },
    "BREACH": {
        "title": "BREACH (compression HTTP)",
        "description": "HTTP compression is enabled on pages containing secrets (CSRF tokens).",
        "remediation": "Disable HTTP compression or implement countermeasures.",
    },
    "POODLE_SSL": {
        "title": "POODLE (SSLv3 CBC)",
        "description": "SSLv3 is supported and vulnerable to the POODLE attack on CBC cipher blocks.",
        "remediation": "Disable SSLv3.",
    },
    "fallback_SCSV": {
        "title": "TLS_FALLBACK_SCSV not supported",
        "description": "The protocol downgrade protection mechanism is not implemented.",
        "remediation": "Update the TLS server to support TLS_FALLBACK_SCSV.",
    },
    "SWEET32": {
        "title": "SWEET32 (CVE-2016-2183)",
        "description": "Ciphers with 64-bit blocks (3DES) vulnerable to the birthday attack.",
        "remediation": "Disable 3DES and ciphers with 64-bit blocks.",
    },
    "FREAK": {
        "title": "FREAK (Factoring RSA Export Keys)",
        "description": "The server accepts RSA export ciphers with short keys (512 bits).",
        "remediation": "Disable export ciphers.",
    },
    "DROWN": {
        "title": "DROWN (CVE-2016-0800)",
        "description": "SSLv2 is supported, allowing decryption of modern TLS connections.",
        "remediation": "Disable SSLv2 on all servers sharing the same private key.",
    },
    "LOGJAM": {
        "title": "LOGJAM (CVE-2015-4000)",
        "description": "Diffie-Hellman parameters too short, vulnerable to pre-computation.",
        "remediation": "Use DH parameters of at least 2048 bits or switch to ECDHE.",
    },
    "BEAST": {
        "title": "BEAST (CVE-2011-3389)",
        "description": "CBC ciphers with TLS 1.0 vulnerable to the Duong and Rizzo attack.",
        "remediation": "Prefer TLS 1.2+ with GCM ciphers, or disable CBC on TLS 1.0.",
    },
    "RC4": {
        "title": "RC4 support",
        "description": "The server accepts RC4 ciphers, considered cryptographically broken.",
        "remediation": "Disable all RC4 ciphers.",
    },
}

# ---------- Server checks (cert chain, OCSP, CT) ----------

_CERT_CHECKS: dict[str, dict] = {
    "cert_chain_of_trust": {
        "title": "Invalid certificate chain",
        "description": "The certificate's chain of trust is incomplete or invalid.",
        "remediation": "Configure the intermediate certificates correctly on the server.",
    },
    "intermediate_cert": {
        "title": "Missing intermediate certificate",
        "description": "The server does not provide all the necessary intermediate certificates.",
        "remediation": "Add the intermediate certificate(s) to the server configuration.",
    },
}

# Special checks: we flag even if severity = INFO/OK, based on the content
_SPECIAL_CHECKS = {
    "OCSP_stapling": {
        "flag_if": "not offered",
        "severity": "medium",
        "title": "OCSP Stapling not enabled",
        "description": "The server does not provide a stapled OCSP response. The browser must contact the CA separately.",
        "remediation": "Enable OCSP Stapling in the web server configuration (ssl_stapling on for nginx).",
    },
    "certificate_transparency": {
        "flag_if": "no ",
        "severity": "medium",
        "title": "Certificate Transparency: SCTs missing",
        "description": "The certificate does not include Signed Certificate Timestamps, required by Chrome.",
        "remediation": "Use a CA that publishes to CT logs (Let's Encrypt does this automatically).",
    },
}


# ---------- Public API ----------


def is_available() -> bool:
    """Checks whether testssl.sh is installed."""
    return os.path.isfile(TESTSSL_PATH) and os.access(TESTSSL_PATH, os.X_OK)


async def run_testssl(domain: str) -> list[FindingData]:
    """Runs testssl.sh and returns the findings. Empty list if unavailable."""
    if not is_available():
        return []

    findings: list[FindingData] = []

    with tempfile.NamedTemporaryFile(suffix=".json", delete=False, mode="w") as tmp:
        json_path = tmp.name

    try:
        proc = await asyncio.create_subprocess_exec(
            TESTSSL_PATH,
            "--quiet",
            "--fast",
            "--ip", "one",
            "--connect-timeout", "10",
            "--openssl-timeout", "10",
            "--jsonfile", json_path,
            "--server-defaults",
            "--vulnerabilities",
            f"{domain}:443",
            stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.DEVNULL,
        )
        await asyncio.wait_for(proc.wait(), timeout=TIMEOUT)

        with open(json_path, "r") as f:
            results = json.load(f)

        for entry in results:
            _process_entry(entry, findings)

    except asyncio.TimeoutError:
        pass
    except (json.JSONDecodeError, FileNotFoundError):
        pass
    finally:
        try:
            os.unlink(json_path)
        except OSError:
            pass

    return findings


# ---------- Parsing ----------


def _process_entry(entry: dict, findings: list[FindingData]) -> None:
    entry_id = entry.get("id", "")
    severity_str = entry.get("severity", "OK")
    finding_text = entry.get("finding", "")

    # Special checks (OCSP, CT): we flag based on the content, not the severity
    if entry_id in _SPECIAL_CHECKS:
        spec = _SPECIAL_CHECKS[entry_id]
        if spec["flag_if"] in finding_text.lower():
            findings.append(FindingData(
                severity=spec["severity"],
                title=spec["title"],
                description=spec["description"],
                remediation=spec["remediation"],
            ))
        return

    # Severity OK → nothing to report
    our_severity = _SEVERITY_MAP.get(severity_str)
    if our_severity is None:
        return

    # Vulnerabilities
    if entry_id in _VULN_CHECKS:
        info = _VULN_CHECKS[entry_id]
        findings.append(FindingData(
            severity=our_severity,
            title=info["title"],
            description=info["description"],
            remediation=info["remediation"],
        ))
        return

    # Cert chain
    if entry_id in _CERT_CHECKS:
        info = _CERT_CHECKS[entry_id]
        findings.append(FindingData(
            severity=our_severity,
            title=info["title"],
            description=info["description"],
            remediation=info["remediation"],
        ))
