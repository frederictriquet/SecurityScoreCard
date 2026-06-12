import asyncio
import logging
import ssl
import socket
from datetime import datetime, timezone

import httpx

from app.scanners.base import BaseScanner, ScanResult, FindingData
from app.scanners.testssl_runner import run_testssl

logger = logging.getLogger(__name__)

WEAK_PROTOCOLS = {
    "SSLv2", "SSLv3", "TLSv1", "TLSv1.1",
    ssl.TLSVersion.TLSv1.name if hasattr(ssl, "TLSVersion") else "TLSv1",
}

WEAK_CIPHERS_KEYWORDS = ["RC4", "DES", "3DES", "EXPORT", "NULL", "MD5", "ANON"]

HSTS_PRELOAD_API = "https://hstspreload.org/api/v2/status"


class TlsScanner(BaseScanner):
    name = "tls"
    weight = 0.20

    async def scan(self, domain: str) -> ScanResult:
        # Run the Python checks, testssl.sh and the HSTS preload check in parallel
        basic_task = self._basic_checks(domain)
        testssl_task = run_testssl(domain)
        preload_task = _check_hsts_preload(domain)

        basic_findings, testssl_findings, preload_findings = await asyncio.gather(
            basic_task, testssl_task, preload_task
        )

        return ScanResult.from_findings(
            basic_findings + testssl_findings + preload_findings
        )

    async def _basic_checks(self, domain: str) -> list[FindingData]:
        findings: list[FindingData] = []

        try:
            cert_info = await _get_cert_info(domain)
        except Exception as exc:
            findings.append(FindingData(
                severity="critical",
                title="TLS connection failed",
                description=f"Unable to establish a TLS connection with {domain}: {exc}",
                remediation="Check that the server supports HTTPS and that the certificate is valid.",
            ))
            return findings

        _check_cert_expiry(cert_info["not_after"], domain, findings)
        _check_tls_version(cert_info["protocol"], findings)
        _check_cipher(cert_info["cipher"], findings)
        _check_self_signed(cert_info, domain, findings)
        _check_key_size(cert_info, findings)
        _check_sig_algorithm(cert_info, findings)
        _check_wildcard_cert(cert_info, findings)
        _check_san_coverage(cert_info, domain, findings)

        return findings


async def _get_cert_info(domain: str) -> dict:
    return await asyncio.get_event_loop().run_in_executor(None, _fetch_cert_sync, domain)


def _fetch_cert_sync(domain: str) -> dict:
    # Try with verification, then without (expired/self-signed cert)
    for verify in (True, False):
        ctx = ssl.create_default_context()
        if not verify:
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        try:
            with socket.create_connection((domain, 443), timeout=10) as sock:
                with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                    der_bytes: bytes = ssock.getpeercert(binary_form=True)  # type: ignore[assignment]
                    cipher = ssock.cipher()
                    protocol = ssock.version()

                    info = _parse_cert_der(der_bytes)
                    info["protocol"] = protocol or ""
                    info["cipher"] = cipher[0] if cipher else ""
                    info["verified"] = verify
                    return info
        except ssl.SSLCertVerificationError:
            if verify:
                continue
            raise

    raise RuntimeError("Unreachable")


def _parse_cert_der(der_bytes: bytes) -> dict:
    """Parses a DER certificate with cryptography if available, otherwise falls back to ssl."""
    try:
        from cryptography import x509 as cx509
        from cryptography.hazmat.primitives.asymmetric import rsa, ec

        cert = cx509.load_der_x509_certificate(der_bytes)
        pub_key = cert.public_key()

        key_size = getattr(pub_key, "key_size", None)
        if isinstance(pub_key, rsa.RSAPublicKey):
            key_type = "RSA"
        elif isinstance(pub_key, ec.EllipticCurvePublicKey):
            key_type = "EC"
        else:
            key_type = type(pub_key).__name__

        sig_hash = cert.signature_hash_algorithm
        sig_algo = sig_hash.name if sig_hash else "unknown"

        not_after = cert.not_valid_after_utc

        from cryptography.x509.oid import NameOID

        try:
            subject_cn = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
        except IndexError:
            subject_cn = ""  # no CN attribute, common on modern certs
        try:
            issuer_cn = cert.issuer.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
        except IndexError:
            issuer_cn = ""

        try:
            san_ext = cert.extensions.get_extension_for_class(
                cx509.SubjectAlternativeName
            )
            sans = san_ext.value.get_values_for_type(cx509.DNSName)
        except cx509.ExtensionNotFound:
            sans = []

        return {
            "not_after": not_after,
            "issuer_cn": issuer_cn,
            "subject_cn": subject_cn,
            "key_size": key_size,
            "key_type": key_type,
            "sig_algo": sig_algo,
            "sans": sans,
            "is_wildcard": any(s.startswith("*.") for s in sans),
        }
    except ImportError:
        # Fallback without cryptography — cannot extract key_size/sig_algo
        return {
            "not_after": datetime.now(timezone.utc),
            "issuer_cn": "",
            "subject_cn": "",
            "key_size": None,
            "key_type": "",
            "sig_algo": "",
            "sans": [],
            "is_wildcard": False,
        }


def _check_cert_expiry(not_after: datetime, domain: str, findings: list) -> None:
    now = datetime.now(timezone.utc)
    remaining = not_after - now
    if remaining.days < 0:
        findings.append(FindingData(
            severity="critical",
            title="TLS certificate expired",
            description=f"The certificate expired on {not_after.strftime('%Y-%m-%d')}.",
            remediation="Renew the certificate immediately (Let's Encrypt, acme.sh...).",
        ))
    elif remaining.days < 15:
        findings.append(FindingData(
            severity="critical",
            title=f"Certificate expires in {remaining.days} day(s)",
            description=f"Imminent expiration on {not_after.strftime('%Y-%m-%d')}.",
            remediation="Renew the certificate urgently.",
        ))
    elif remaining.days < 30:
        findings.append(FindingData(
            severity="high",
            title=f"Certificate expires in {remaining.days} days",
            description=f"Expiration on {not_after.strftime('%Y-%m-%d')}.",
            remediation="Plan the certificate renewal.",
        ))


def _check_tls_version(protocol: str, findings: list) -> None:
    if any(weak in protocol for weak in ["SSLv2", "SSLv3", "TLSv1.0", "TLSv1.1"]):
        findings.append(FindingData(
            severity="high",
            title=f"Obsolete protocol: {protocol}",
            description=f"The server uses {protocol}, a deprecated and vulnerable version.",
            remediation="Disable TLS < 1.2 and prefer TLS 1.3.",
        ))


def _check_cipher(cipher: str, findings: list) -> None:
    for keyword in WEAK_CIPHERS_KEYWORDS:
        if keyword in cipher.upper():
            findings.append(FindingData(
                severity="high",
                title=f"Weak cipher suite: {cipher}",
                description=f"The negotiated encryption suite contains '{keyword}', considered weak.",
                remediation="Configure the server to accept only modern ciphers (AES-GCM, ChaCha20).",
            ))
            break


def _check_self_signed(cert_info: dict, domain: str, findings: list) -> None:
    if cert_info["issuer_cn"] and cert_info["issuer_cn"] == cert_info["subject_cn"]:
        findings.append(FindingData(
            severity="critical",
            title="Self-signed certificate",
            description="The certificate is signed by itself, not recognized by browsers.",
            remediation="Use a certificate signed by a recognized CA (Let's Encrypt is free).",
        ))


# --- Phase 1: new checks ---


def _check_key_size(cert_info: dict, findings: list) -> None:
    key_type = cert_info.get("key_type", "")
    key_size = cert_info.get("key_size")
    if not key_size:
        return

    if key_type == "RSA" and key_size < 2048:
        findings.append(FindingData(
            severity="high",
            title=f"RSA key too short ({key_size} bits)",
            description="RSA keys below 2048 bits are considered weak and breakable.",
            remediation="Regenerate the certificate with an RSA key of at least 2048 bits (4096 recommended).",
        ))
    elif key_type == "EC" and key_size < 256:
        findings.append(FindingData(
            severity="high",
            title=f"ECC key too short ({key_size} bits)",
            description="ECC keys below 256 bits are considered weak.",
            remediation="Regenerate the certificate with a P-256 curve minimum.",
        ))


def _check_sig_algorithm(cert_info: dict, findings: list) -> None:
    sig = cert_info.get("sig_algo", "").lower()
    if not sig:
        return

    if "md5" in sig:
        findings.append(FindingData(
            severity="critical",
            title="Certificate signed with MD5",
            description="MD5 is vulnerable to collisions. The certificate can be forged.",
            remediation="Regenerate the certificate with SHA-256 or higher.",
        ))
    elif "sha1" in sig:
        findings.append(FindingData(
            severity="high",
            title="Certificate signed with SHA-1",
            description="SHA-1 is deprecated and vulnerable to collision attacks.",
            remediation="Regenerate the certificate with SHA-256 or higher.",
        ))


def _check_wildcard_cert(cert_info: dict, findings: list) -> None:
    sans = cert_info.get("sans", [])
    wildcards = [s for s in sans if s.startswith("*.")]
    if not wildcards:
        return
    # Wildcard on a TLD or second-level domain = too broad
    for w in wildcards:
        parts = w[2:].split(".")
        if len(parts) <= 1:
            findings.append(FindingData(
                severity="high",
                title=f"Excessively broad wildcard certificate: {w}",
                description=f"The certificate covers {w}, a dangerously broad scope.",
                remediation="Use certificates specific to the required subdomains.",
            ))
            return
    if len(wildcards) >= 1:
        findings.append(FindingData(
            severity="medium",
            title=f"Wildcard certificate ({', '.join(wildcards[:3])})",
            description="A wildcard certificate covers all subdomains. If the private key is compromised, all are affected.",
            remediation="Consider service-specific certificates to limit the impact of a compromise.",
        ))


def _check_san_coverage(cert_info: dict, domain: str, findings: list) -> None:
    sans = cert_info.get("sans", [])
    if not sans:
        findings.append(FindingData(
            severity="low",
            title="Certificate without SAN extension",
            description="The certificate does not contain Subject Alternative Names. Modern browsers require this extension.",
            remediation="Regenerate the certificate including the appropriate SANs.",
        ))
        return
    # Check that the scanned domain is covered by the SANs
    covered = any(
        s == domain or (s.startswith("*.") and domain.endswith(s[1:]))
        for s in sans
    )
    if not covered:
        findings.append(FindingData(
            severity="medium",
            title=f"Domain {domain} not covered by the certificate SANs",
            description=f"The certificate SANs ({', '.join(sans[:5])}) do not cover {domain}.",
            remediation="Regenerate the certificate including the domain in the SANs.",
        ))


async def _check_hsts_preload(domain: str) -> list[FindingData]:
    """Check whether the domain is in the browsers' HSTS preload list.

    Queries the free hstspreload.org API. The JSON response carries a
    "status" field: "preloaded" (OK), "pending" (submission in progress),
    or "unknown"/absent (not in the list).
    """
    findings: list[FindingData] = []

    try:
        async with httpx.AsyncClient(timeout=10) as client:
            resp = await client.get(HSTS_PRELOAD_API, params={"domain": domain})
            resp.raise_for_status()
            data = resp.json()
    except (httpx.HTTPError, ValueError) as exc:
        # Network error, timeout or invalid response: do not break the scan
        logger.warning("tls: HSTS preload check failed for %s: %s", domain, exc)
        return findings

    status = data.get("status") if isinstance(data, dict) else None

    if status == "preloaded":
        return findings

    findings.append(FindingData(
        severity="medium",
        title="Domain not in the HSTS preload list",
        description=(
            f"{domain} is not present in the browsers' HSTS preload list "
            f"(status: {status or 'unknown'}). Without preloading, the first "
            "visit before any HSTS header is received remains exposed to "
            "SSL-stripping / downgrade attacks."
        ),
        remediation=(
            "Serve a Strict-Transport-Security header with the 'preload' and "
            "'includeSubDomains' directives and a max-age of at least one year "
            "(max-age=31536000), then submit the domain at "
            "https://hstspreload.org."
        ),
    ))

    return findings
