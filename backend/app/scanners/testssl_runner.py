"""Wrapper async pour testssl.sh — exécute les checks vulnérabilités + server-defaults."""

import asyncio
import json
import os
import tempfile

from app.scanners.base import FindingData

TESTSSL_PATH = os.environ.get("TESTSSL_PATH", "/opt/testssl/testssl.sh")
TIMEOUT = 120  # secondes max pour un run complet

# ---------- Mapping severity testssl → notre modèle ----------

_SEVERITY_MAP = {
    "CRITICAL": "critical",
    "HIGH": "high",
    "MEDIUM": "medium",
    "LOW": "low",
    "WARN": "medium",
}

# ---------- Vulnérabilités TLS connues ----------

_VULN_CHECKS: dict[str, dict] = {
    "heartbleed": {
        "title": "Heartbleed (CVE-2014-0160)",
        "description": "Le serveur est vulnérable à Heartbleed, permettant la lecture de la mémoire du serveur.",
        "remediation": "Mettre à jour OpenSSL et régénérer les certificats et clés privées.",
    },
    "CCS": {
        "title": "CCS Injection (CVE-2014-0224)",
        "description": "Vulnérabilité d'injection CCS permettant un man-in-the-middle.",
        "remediation": "Mettre à jour OpenSSL.",
    },
    "ticketbleed": {
        "title": "Ticketbleed (CVE-2016-9244)",
        "description": "Fuite de mémoire via les tickets de session TLS (F5 BIG-IP).",
        "remediation": "Mettre à jour le firmware F5 BIG-IP.",
    },
    "ROBOT": {
        "title": "ROBOT (Return Of Bleichenbacher's Oracle Threat)",
        "description": "Oracle de padding RSA PKCS#1 v1.5, permettant le déchiffrement passif du trafic.",
        "remediation": "Désactiver RSA key exchange ou mettre à jour le serveur TLS.",
    },
    "secure_renego": {
        "title": "Renégociation TLS non sécurisée (CVE-2009-3555)",
        "description": "Le serveur supporte la renégociation non sécurisée, vulnérable au prefix injection.",
        "remediation": "Activer la renégociation sécurisée (RFC 5746).",
    },
    "CRIME_TLS": {
        "title": "CRIME (Compression TLS activée)",
        "description": "La compression TLS est activée, permettant la fuite de secrets via les ratios de compression.",
        "remediation": "Désactiver la compression TLS.",
    },
    "BREACH": {
        "title": "BREACH (compression HTTP)",
        "description": "La compression HTTP est activée sur des pages contenant des secrets (tokens CSRF).",
        "remediation": "Désactiver la compression HTTP ou implémenter des contre-mesures.",
    },
    "POODLE_SSL": {
        "title": "POODLE (SSLv3 CBC)",
        "description": "SSLv3 est supporté et vulnérable à l'attaque POODLE sur les cipher blocks CBC.",
        "remediation": "Désactiver SSLv3.",
    },
    "fallback_SCSV": {
        "title": "TLS_FALLBACK_SCSV non supporté",
        "description": "Le mécanisme de protection contre le downgrade de protocole n'est pas implémenté.",
        "remediation": "Mettre à jour le serveur TLS pour supporter TLS_FALLBACK_SCSV.",
    },
    "SWEET32": {
        "title": "SWEET32 (CVE-2016-2183)",
        "description": "Ciphers avec blocs de 64 bits (3DES) vulnérables à l'attaque birthday.",
        "remediation": "Désactiver 3DES et les ciphers avec blocs de 64 bits.",
    },
    "FREAK": {
        "title": "FREAK (Factoring RSA Export Keys)",
        "description": "Le serveur accepte des ciphers export RSA avec clés courtes (512 bits).",
        "remediation": "Désactiver les ciphers export.",
    },
    "DROWN": {
        "title": "DROWN (CVE-2016-0800)",
        "description": "SSLv2 est supporté, permettant le déchiffrement de connexions TLS modernes.",
        "remediation": "Désactiver SSLv2 sur tous les serveurs partageant la même clé privée.",
    },
    "LOGJAM": {
        "title": "LOGJAM (CVE-2015-4000)",
        "description": "Paramètres Diffie-Hellman trop courts, vulnérables à la pré-computation.",
        "remediation": "Utiliser des paramètres DH d'au moins 2048 bits ou passer à ECDHE.",
    },
    "BEAST": {
        "title": "BEAST (CVE-2011-3389)",
        "description": "CBC ciphers avec TLS 1.0 vulnérables à l'attaque de Duong et Rizzo.",
        "remediation": "Préférer TLS 1.2+ avec des ciphers GCM, ou désactiver CBC sur TLS 1.0.",
    },
    "RC4": {
        "title": "Support de RC4",
        "description": "Le serveur accepte des ciphers RC4, considérés cryptographiquement cassés.",
        "remediation": "Désactiver tous les ciphers RC4.",
    },
}

# ---------- Checks serveur (cert chain, OCSP, CT) ----------

_CERT_CHECKS: dict[str, dict] = {
    "cert_chain_of_trust": {
        "title": "Chaîne de certificats invalide",
        "description": "La chaîne de confiance du certificat est incomplète ou invalide.",
        "remediation": "Configurer les certificats intermédiaires correctement sur le serveur.",
    },
    "intermediate_cert": {
        "title": "Certificat intermédiaire manquant",
        "description": "Le serveur ne fournit pas tous les certificats intermédiaires nécessaires.",
        "remediation": "Ajouter le(s) certificat(s) intermédiaire(s) à la configuration du serveur.",
    },
}

# Checks spéciaux : on flag même si severity = INFO/OK, selon le contenu
_SPECIAL_CHECKS = {
    "OCSP_stapling": {
        "flag_if": "not offered",
        "severity": "medium",
        "title": "OCSP Stapling non activé",
        "description": "Le serveur ne fournit pas de réponse OCSP agrafée. Le navigateur doit contacter le CA séparément.",
        "remediation": "Activer OCSP Stapling dans la configuration du serveur web (ssl_stapling on pour nginx).",
    },
    "certificate_transparency": {
        "flag_if": "no ",
        "severity": "medium",
        "title": "Certificate Transparency : SCT manquants",
        "description": "Le certificat n'inclut pas de Signed Certificate Timestamps, requis par Chrome.",
        "remediation": "Utiliser un CA qui publie dans les logs CT (Let's Encrypt le fait automatiquement).",
    },
}


# ---------- API publique ----------


def is_available() -> bool:
    """Vérifie si testssl.sh est installé."""
    return os.path.isfile(TESTSSL_PATH) and os.access(TESTSSL_PATH, os.X_OK)


async def run_testssl(domain: str) -> list[FindingData]:
    """Exécute testssl.sh et retourne les findings. Liste vide si non disponible."""
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

    # Checks spéciaux (OCSP, CT) : on flag selon le contenu, pas la severity
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

    # Severity OK → rien à signaler
    our_severity = _SEVERITY_MAP.get(severity_str)
    if our_severity is None:
        return

    # Vulnérabilités
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
