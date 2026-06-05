import asyncio
import ssl
import socket
from datetime import datetime, timezone

from app.scanners.base import BaseScanner, ScanResult, FindingData
from app.scanners.testssl_runner import run_testssl

WEAK_PROTOCOLS = {
    "SSLv2", "SSLv3", "TLSv1", "TLSv1.1",
    ssl.TLSVersion.TLSv1.name if hasattr(ssl, "TLSVersion") else "TLSv1",
}

WEAK_CIPHERS_KEYWORDS = ["RC4", "DES", "3DES", "EXPORT", "NULL", "MD5", "ANON"]


class TlsScanner(BaseScanner):
    name = "tls"
    weight = 0.20

    async def scan(self, domain: str) -> ScanResult:
        # Run the Python checks and testssl.sh in parallel
        basic_task = self._basic_checks(domain)
        testssl_task = run_testssl(domain)

        basic_findings, testssl_findings = await asyncio.gather(
            basic_task, testssl_task
        )

        return ScanResult.from_findings(basic_findings + testssl_findings)

    async def _basic_checks(self, domain: str) -> list[FindingData]:
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
        except (IndexError, Exception):
            subject_cn = ""
        try:
            issuer_cn = cert.issuer.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
        except (IndexError, Exception):
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
    if cert_info["issuer_cn"] and cert_info["issuer_cn"] == cert_info["subject_cn"]:
        findings.append(FindingData(
            severity="critical",
            title="Certificat auto-signé",
            description="Le certificat est signé par lui-même, non reconnu par les navigateurs.",
            remediation="Utiliser un certificat signé par une CA reconnue (Let's Encrypt est gratuit).",
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
            title=f"Clé RSA trop courte ({key_size} bits)",
            description="Les clés RSA inférieures à 2048 bits sont considérées faibles et cassables.",
            remediation="Régénérer le certificat avec une clé RSA de 2048 bits minimum (4096 recommandé).",
        ))
    elif key_type == "EC" and key_size < 256:
        findings.append(FindingData(
            severity="high",
            title=f"Clé ECC trop courte ({key_size} bits)",
            description="Les clés ECC inférieures à 256 bits sont considérées faibles.",
            remediation="Régénérer le certificat avec une courbe P-256 minimum.",
        ))


def _check_sig_algorithm(cert_info: dict, findings: list) -> None:
    sig = cert_info.get("sig_algo", "").lower()
    if not sig:
        return

    if "md5" in sig:
        findings.append(FindingData(
            severity="critical",
            title="Certificat signé avec MD5",
            description="MD5 est vulnérable aux collisions. Le certificat peut être falsifié.",
            remediation="Régénérer le certificat avec SHA-256 ou supérieur.",
        ))
    elif "sha1" in sig:
        findings.append(FindingData(
            severity="high",
            title="Certificat signé avec SHA-1",
            description="SHA-1 est déprécié et vulnérable aux attaques par collision.",
            remediation="Régénérer le certificat avec SHA-256 ou supérieur.",
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
                title=f"Certificat wildcard excessivement large : {w}",
                description=f"Le certificat couvre {w}, un périmètre dangereusement large.",
                remediation="Utiliser des certificats spécifiques aux sous-domaines nécessaires.",
            ))
            return
    if len(wildcards) >= 1:
        findings.append(FindingData(
            severity="medium",
            title=f"Certificat wildcard ({', '.join(wildcards[:3])})",
            description="Un certificat wildcard couvre tous les sous-domaines. Si la clé privée est compromise, tous sont affectés.",
            remediation="Envisager des certificats spécifiques par service pour limiter l'impact d'une compromission.",
        ))


def _check_san_coverage(cert_info: dict, domain: str, findings: list) -> None:
    sans = cert_info.get("sans", [])
    if not sans:
        findings.append(FindingData(
            severity="low",
            title="Certificat sans extension SAN",
            description="Le certificat ne contient pas de Subject Alternative Names. Les navigateurs modernes exigent cette extension.",
            remediation="Régénérer le certificat en incluant les SANs appropriés.",
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
            title=f"Domaine {domain} non couvert par les SANs du certificat",
            description=f"Les SANs du certificat ({', '.join(sans[:5])}) ne couvrent pas {domain}.",
            remediation="Régénérer le certificat en incluant le domaine dans les SANs.",
        ))
