import ssl
import socket
from datetime import datetime, timezone

from app.scanners.base import BaseScanner, ScanResult, FindingData

WEAK_PROTOCOLS = {
    "SSLv2", "SSLv3", "TLSv1", "TLSv1.1",
    ssl.TLSVersion.TLSv1.name if hasattr(ssl, "TLSVersion") else "TLSv1",
}

WEAK_CIPHERS_KEYWORDS = ["RC4", "DES", "3DES", "EXPORT", "NULL", "MD5", "ANON"]


class TlsScanner(BaseScanner):
    name = "tls"
    weight = 0.20

    async def scan(self, domain: str) -> ScanResult:
        findings: list[FindingData] = []

        try:
            cert_info = await _get_cert_info(domain)
        except Exception as exc:
            findings.append(FindingData(
                severity="critical",
                title="Connexion TLS impossible",
                description=f"Impossible d'établir une connexion TLS avec {domain} : {exc}",
                remediation="Vérifier que le serveur supporte HTTPS et que le certificat est valide.",
            ))
            return ScanResult.from_findings(findings)

        _check_cert_expiry(cert_info["not_after"], domain, findings)
        _check_tls_version(cert_info["protocol"], findings)
        _check_cipher(cert_info["cipher"], findings)
        _check_self_signed(cert_info, domain, findings)

        return ScanResult.from_findings(findings)


async def _get_cert_info(domain: str) -> dict:
    import asyncio
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(None, _fetch_cert_sync, domain)


def _fetch_cert_sync(domain: str) -> dict:
    ctx = ssl.create_default_context()
    with socket.create_connection((domain, 443), timeout=10) as sock:
        with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
            cert: dict = ssock.getpeercert()  # type: ignore[assignment]
            assert cert is not None
            cipher = ssock.cipher()
            protocol = ssock.version()
            not_after_str: str = str(cert["notAfter"])
            not_after = datetime.strptime(not_after_str, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
            issuer: dict = {k: v for rdn in cert.get("issuer", ()) for k, v in rdn}
            subject: dict = {k: v for rdn in cert.get("subject", ()) for k, v in rdn}
            return {
                "not_after": not_after,
                "protocol": protocol or "",
                "cipher": cipher[0] if cipher else "",
                "issuer_cn": issuer.get("commonName", ""),
                "subject_cn": subject.get("commonName", ""),
            }


def _check_cert_expiry(not_after: datetime, domain: str, findings: list) -> None:
    now = datetime.now(timezone.utc)
    remaining = not_after - now
    if remaining.days < 0:
        findings.append(FindingData(
            severity="critical",
            title="Certificat TLS expiré",
            description=f"Le certificat a expiré le {not_after.strftime('%Y-%m-%d')}.",
            remediation="Renouveler immédiatement le certificat (Let's Encrypt, acme.sh...).",
        ))
    elif remaining.days < 15:
        findings.append(FindingData(
            severity="critical",
            title=f"Certificat expire dans {remaining.days} jour(s)",
            description=f"Expiration imminente le {not_after.strftime('%Y-%m-%d')}.",
            remediation="Renouveler le certificat en urgence.",
        ))
    elif remaining.days < 30:
        findings.append(FindingData(
            severity="high",
            title=f"Certificat expire dans {remaining.days} jours",
            description=f"Expiration le {not_after.strftime('%Y-%m-%d')}.",
            remediation="Planifier le renouvellement du certificat.",
        ))


def _check_tls_version(protocol: str, findings: list) -> None:
    if any(weak in protocol for weak in ["SSLv2", "SSLv3", "TLSv1.0", "TLSv1.1"]):
        findings.append(FindingData(
            severity="high",
            title=f"Protocole obsolète : {protocol}",
            description=f"Le serveur utilise {protocol}, une version dépréciée et vulnérable.",
            remediation="Désactiver TLS < 1.2 et privilégier TLS 1.3.",
        ))


def _check_cipher(cipher: str, findings: list) -> None:
    for keyword in WEAK_CIPHERS_KEYWORDS:
        if keyword in cipher.upper():
            findings.append(FindingData(
                severity="high",
                title=f"Cipher suite faible : {cipher}",
                description=f"La suite de chiffrement négociée contient '{keyword}', considérée faible.",
                remediation="Configurer le serveur pour n'accepter que des ciphers modernes (AES-GCM, ChaCha20).",
            ))
            break


def _check_self_signed(cert_info: dict, domain: str, findings: list) -> None:
    if cert_info["issuer_cn"] == cert_info["subject_cn"]:
        findings.append(FindingData(
            severity="critical",
            title="Certificat auto-signé",
            description="Le certificat est signé par lui-même, non reconnu par les navigateurs.",
            remediation="Utiliser un certificat signé par une CA reconnue (Let's Encrypt est gratuit).",
        ))
