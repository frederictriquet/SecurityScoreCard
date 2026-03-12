"""Tests pour app.scanners.tls — TlsScanner et fonctions auxiliaires."""

import pytest
import ssl
import socket
from unittest.mock import patch, AsyncMock, MagicMock
from datetime import datetime, timezone, timedelta

from app.scanners.tls import (
    TlsScanner,
    _check_cert_expiry,
    _check_tls_version,
    _check_cipher,
    _check_self_signed,
    _check_key_size,
    _check_sig_algorithm,
    _check_wildcard_cert,
    _check_san_coverage,
    _fetch_cert_sync,
    _parse_cert_der,
    _get_cert_info,
    WEAK_CIPHERS_KEYWORDS,
)
from app.scanners.base import FindingData
from tests.conftest import make_cert_info


@pytest.fixture
def scanner():
    return TlsScanner()


# ===================================================================
# Certificate Expiry
# ===================================================================


class TestCertExpiry:
    def test_valid_cert_no_finding(self):
        not_after = datetime.now(timezone.utc) + timedelta(days=90)
        findings = []
        _check_cert_expiry(not_after, "example.com", findings)
        assert len(findings) == 0

    def test_expired_cert(self):
        not_after = datetime.now(timezone.utc) - timedelta(days=1)
        findings = []
        _check_cert_expiry(not_after, "example.com", findings)
        assert len(findings) == 1
        assert findings[0].severity == "critical"
        assert "expiré" in findings[0].title.lower()

    def test_expires_in_less_than_15_days(self):
        not_after = datetime.now(timezone.utc) + timedelta(days=10)
        findings = []
        _check_cert_expiry(not_after, "example.com", findings)
        assert len(findings) == 1
        assert findings[0].severity == "critical"
        # Le nombre exact de jours peut varier de ±1 selon l'heure d'exécution
        assert "jour" in findings[0].title

    def test_expires_in_less_than_30_days(self):
        not_after = datetime.now(timezone.utc) + timedelta(days=20)
        findings = []
        _check_cert_expiry(not_after, "example.com", findings)
        assert len(findings) == 1
        assert findings[0].severity == "high"
        assert "jours" in findings[0].title

    def test_expires_in_exactly_15_days(self):
        """15 jours restants : le remaining.days peut être 14 (< 15 → critical) ou 15 (< 30 → high)."""
        not_after = datetime.now(timezone.utc) + timedelta(days=15)
        findings = []
        _check_cert_expiry(not_after, "example.com", findings)
        assert len(findings) == 1
        assert findings[0].severity in ("critical", "high")

    def test_expires_in_exactly_30_days(self):
        """30 jours restants : remaining.days peut être 29 (< 30 → high) ou 30 (pas de finding)."""
        not_after = datetime.now(timezone.utc) + timedelta(days=30)
        findings = []
        _check_cert_expiry(not_after, "example.com", findings)
        # Peut être 0 ou 1 finding selon le moment exact de l'exécution
        assert len(findings) <= 1

    def test_expires_in_1_day(self):
        not_after = datetime.now(timezone.utc) + timedelta(days=1)
        findings = []
        _check_cert_expiry(not_after, "example.com", findings)
        assert findings[0].severity == "critical"


# ===================================================================
# TLS Version
# ===================================================================


class TestTlsVersion:
    @pytest.mark.parametrize("protocol", ["TLSv1.2", "TLSv1.3"])
    def test_modern_protocols_no_finding(self, protocol):
        findings = []
        _check_tls_version(protocol, findings)
        assert len(findings) == 0

    @pytest.mark.parametrize("protocol", ["SSLv2", "SSLv3", "TLSv1.0", "TLSv1.1"])
    def test_weak_protocols_generate_finding(self, protocol):
        findings = []
        _check_tls_version(protocol, findings)
        assert len(findings) == 1
        assert findings[0].severity == "high"
        assert protocol in findings[0].title

    def test_empty_protocol(self):
        findings = []
        _check_tls_version("", findings)
        assert len(findings) == 0


# ===================================================================
# Cipher suites
# ===================================================================


class TestCipher:
    def test_strong_cipher_no_finding(self):
        findings = []
        _check_cipher("TLS_AES_256_GCM_SHA384", findings)
        assert len(findings) == 0

    @pytest.mark.parametrize("keyword", WEAK_CIPHERS_KEYWORDS)
    def test_weak_cipher_keywords(self, keyword):
        findings = []
        _check_cipher(f"TLS_{keyword}_SOMETHING", findings)
        assert len(findings) == 1
        assert findings[0].severity == "high"

    def test_rc4_in_cipher_name(self):
        findings = []
        _check_cipher("RC4-SHA", findings)
        assert len(findings) == 1

    def test_des_in_cipher_name(self):
        findings = []
        _check_cipher("DES-CBC3-SHA", findings)
        assert len(findings) == 1

    def test_case_insensitive_detection(self):
        findings = []
        _check_cipher("tls_null_with_null_null", findings)
        assert len(findings) == 1


# ===================================================================
# Self-signed certificate
# ===================================================================


class TestSelfSigned:
    def test_not_self_signed(self):
        cert_info = make_cert_info(
            issuer_cn="Let's Encrypt Authority X3",
            subject_cn="example.com",
        )
        findings = []
        _check_self_signed(cert_info, "example.com", findings)
        assert len(findings) == 0

    def test_self_signed_detected(self):
        cert_info = make_cert_info(
            issuer_cn="example.com",
            subject_cn="example.com",
        )
        findings = []
        _check_self_signed(cert_info, "example.com", findings)
        assert len(findings) == 1
        assert findings[0].severity == "critical"
        assert "auto-signé" in findings[0].title

    def test_empty_issuer_no_false_positive(self):
        cert_info = make_cert_info(issuer_cn="", subject_cn="example.com")
        findings = []
        _check_self_signed(cert_info, "example.com", findings)
        assert len(findings) == 0

    def test_both_empty_no_false_positive(self):
        cert_info = make_cert_info(issuer_cn="", subject_cn="")
        findings = []
        _check_self_signed(cert_info, "example.com", findings)
        assert len(findings) == 0


# ===================================================================
# Key Size
# ===================================================================


class TestKeySize:
    def test_rsa_2048_ok(self):
        cert_info = make_cert_info(key_type="RSA", key_size=2048)
        findings = []
        _check_key_size(cert_info, findings)
        assert len(findings) == 0

    def test_rsa_4096_ok(self):
        cert_info = make_cert_info(key_type="RSA", key_size=4096)
        findings = []
        _check_key_size(cert_info, findings)
        assert len(findings) == 0

    def test_rsa_1024_weak(self):
        cert_info = make_cert_info(key_type="RSA", key_size=1024)
        findings = []
        _check_key_size(cert_info, findings)
        assert len(findings) == 1
        assert findings[0].severity == "high"
        assert "1024" in findings[0].title

    def test_rsa_512_weak(self):
        cert_info = make_cert_info(key_type="RSA", key_size=512)
        findings = []
        _check_key_size(cert_info, findings)
        assert len(findings) == 1

    def test_ec_256_ok(self):
        cert_info = make_cert_info(key_type="EC", key_size=256)
        findings = []
        _check_key_size(cert_info, findings)
        assert len(findings) == 0

    def test_ec_384_ok(self):
        cert_info = make_cert_info(key_type="EC", key_size=384)
        findings = []
        _check_key_size(cert_info, findings)
        assert len(findings) == 0

    def test_ec_224_weak(self):
        cert_info = make_cert_info(key_type="EC", key_size=224)
        findings = []
        _check_key_size(cert_info, findings)
        assert len(findings) == 1
        assert findings[0].severity == "high"
        assert "224" in findings[0].title

    def test_no_key_size_skips(self):
        cert_info = make_cert_info(key_size=None)
        findings = []
        _check_key_size(cert_info, findings)
        assert len(findings) == 0

    def test_unknown_key_type_no_finding(self):
        cert_info = make_cert_info(key_type="Ed25519", key_size=256)
        findings = []
        _check_key_size(cert_info, findings)
        assert len(findings) == 0


# ===================================================================
# Signature Algorithm
# ===================================================================


class TestSigAlgorithm:
    def test_sha256_ok(self):
        cert_info = make_cert_info(sig_algo="sha256")
        findings = []
        _check_sig_algorithm(cert_info, findings)
        assert len(findings) == 0

    def test_sha384_ok(self):
        cert_info = make_cert_info(sig_algo="sha384")
        findings = []
        _check_sig_algorithm(cert_info, findings)
        assert len(findings) == 0

    def test_sha512_ok(self):
        cert_info = make_cert_info(sig_algo="sha512")
        findings = []
        _check_sig_algorithm(cert_info, findings)
        assert len(findings) == 0

    def test_md5_critical(self):
        cert_info = make_cert_info(sig_algo="md5WithRSAEncryption")
        findings = []
        _check_sig_algorithm(cert_info, findings)
        assert len(findings) == 1
        assert findings[0].severity == "critical"
        assert "MD5" in findings[0].title

    def test_sha1_high(self):
        cert_info = make_cert_info(sig_algo="sha1WithRSAEncryption")
        findings = []
        _check_sig_algorithm(cert_info, findings)
        assert len(findings) == 1
        assert findings[0].severity == "high"
        assert "SHA-1" in findings[0].title

    def test_empty_sig_algo_skips(self):
        cert_info = make_cert_info(sig_algo="")
        findings = []
        _check_sig_algorithm(cert_info, findings)
        assert len(findings) == 0

    def test_md5_case_insensitive(self):
        cert_info = make_cert_info(sig_algo="MD5WithRSA")
        findings = []
        _check_sig_algorithm(cert_info, findings)
        assert len(findings) == 1


# ===================================================================
# Full scan — TLS connection failure
# ===================================================================


class TestTlsFullScan:
    async def test_connection_failure_returns_critical(self, scanner):
        with patch("app.scanners.tls._get_cert_info", new_callable=AsyncMock) as mock:
            mock.side_effect = Exception("Connection refused")
            result = await scanner.scan("unreachable.example.com")
            assert result.score == 70  # 100 - 30 (critical)
            assert len(result.findings) == 1
            assert result.findings[0].severity == "critical"
            assert "Connexion TLS impossible" in result.findings[0].title

    async def test_healthy_cert_returns_100(self, scanner):
        with patch("app.scanners.tls._get_cert_info", new_callable=AsyncMock) as mock:
            mock.return_value = make_cert_info(sans=["healthy.example.com", "www.healthy.example.com"])
            result = await scanner.scan("healthy.example.com")
            assert result.score == 100
            assert len(result.findings) == 0

    async def test_multiple_issues_cumulate(self, scanner):
        with patch("app.scanners.tls._get_cert_info", new_callable=AsyncMock) as mock:
            mock.return_value = make_cert_info(
                not_after=datetime.now(timezone.utc) - timedelta(days=5),  # expired → critical
                issuer_cn="self.example.com",
                subject_cn="self.example.com",  # self-signed → critical
                sig_algo="sha1WithRSA",  # sha1 → high
                sans=["bad.example.com"],  # domaine couvert pour éviter finding SAN
            )
            result = await scanner.scan("bad.example.com")
            # critical(-30) + critical(-30) + high(-20) = 100 - 80 = 20
            assert result.score == 20
            assert len(result.findings) == 3


# ===================================================================
# _fetch_cert_sync — logique de connexion SSL
# ===================================================================


def _make_mock_ssock(der_bytes=b"FAKE_DER", cipher_tuple=("TLS_AES_256_GCM_SHA384", "TLSv1.3", 256), version="TLSv1.3"):
    """Crée un mock de SSLSocket avec getpeercert, cipher, version."""
    ssock = MagicMock()
    ssock.getpeercert.return_value = der_bytes
    ssock.cipher.return_value = cipher_tuple
    ssock.version.return_value = version
    ssock.__enter__ = MagicMock(return_value=ssock)
    ssock.__exit__ = MagicMock(return_value=False)
    return ssock


def _make_mock_sock():
    """Crée un mock de socket.socket avec context manager."""
    sock = MagicMock()
    sock.__enter__ = MagicMock(return_value=sock)
    sock.__exit__ = MagicMock(return_value=False)
    return sock


class TestFetchCertSync:
    def test_successful_verified_connection(self):
        """Connexion réussie avec vérification SSL — verify=True au premier essai."""
        mock_sock = _make_mock_sock()
        mock_ssock = _make_mock_ssock()
        mock_ctx = MagicMock()
        mock_ctx.wrap_socket.return_value = mock_ssock

        parsed = {
            "not_after": datetime(2026, 12, 31, tzinfo=timezone.utc),
            "issuer_cn": "Let's Encrypt",
            "subject_cn": "example.com",
            "key_size": 2048,
            "key_type": "RSA",
            "sig_algo": "sha256",
            "is_wildcard": False,
        }

        with (
            patch("socket.create_connection", return_value=mock_sock) as mock_conn,
            patch("ssl.create_default_context", return_value=mock_ctx),
            patch("app.scanners.tls._parse_cert_der", return_value=parsed) as mock_parse,
        ):
            result = _fetch_cert_sync("example.com")

        # Vérifie que _parse_cert_der est appelé avec les bytes DER
        mock_parse.assert_called_once_with(b"FAKE_DER")
        # Vérifie les champs ajoutés par _fetch_cert_sync
        assert result["protocol"] == "TLSv1.3"
        assert result["cipher"] == "TLS_AES_256_GCM_SHA384"
        assert result["verified"] is True
        # Vérifie que la connexion est faite sur le port 443
        mock_conn.assert_called_once_with(("example.com", 443), timeout=10)

    def test_fallback_to_unverified_on_cert_error(self):
        """SSLCertVerificationError sur verify=True → retry avec verify=False."""
        mock_sock = _make_mock_sock()
        mock_ssock = _make_mock_ssock()

        ctx_verified = MagicMock()
        ctx_verified.wrap_socket.side_effect = ssl.SSLCertVerificationError("cert expired")

        ctx_unverified = MagicMock()
        ctx_unverified.wrap_socket.return_value = mock_ssock

        parsed = {
            "not_after": datetime(2025, 1, 1, tzinfo=timezone.utc),
            "issuer_cn": "Expired CA",
            "subject_cn": "example.com",
            "key_size": 2048,
            "key_type": "RSA",
            "sig_algo": "sha256",
            "is_wildcard": False,
        }

        with (
            patch("socket.create_connection", return_value=mock_sock),
            patch("ssl.create_default_context", side_effect=[ctx_verified, ctx_unverified]),
            patch("app.scanners.tls._parse_cert_der", return_value=parsed),
        ):
            result = _fetch_cert_sync("example.com")

        assert result["verified"] is False
        # La deuxième tentative désactive la vérification
        assert ctx_unverified.check_hostname is False
        assert ctx_unverified.verify_mode == ssl.CERT_NONE

    def test_raises_when_both_attempts_fail(self):
        """SSLCertVerificationError sur les deux tentatives → raise."""
        mock_sock = _make_mock_sock()

        ctx_verified = MagicMock()
        ctx_verified.wrap_socket.side_effect = ssl.SSLCertVerificationError("cert error")

        ctx_unverified = MagicMock()
        ctx_unverified.wrap_socket.side_effect = ssl.SSLCertVerificationError("still bad")

        with (
            patch("socket.create_connection", return_value=mock_sock),
            patch("ssl.create_default_context", side_effect=[ctx_verified, ctx_unverified]),
        ):
            with pytest.raises(ssl.SSLCertVerificationError):
                _fetch_cert_sync("bad.example.com")

    def test_cipher_returns_none(self):
        """cipher() retourne None → cipher vide dans le résultat."""
        mock_sock = _make_mock_sock()
        mock_ssock = _make_mock_ssock()
        mock_ssock.cipher.return_value = None

        mock_ctx = MagicMock()
        mock_ctx.wrap_socket.return_value = mock_ssock

        parsed = {
            "not_after": datetime(2026, 12, 31, tzinfo=timezone.utc),
            "issuer_cn": "CA", "subject_cn": "x.com",
            "key_size": 2048, "key_type": "RSA", "sig_algo": "sha256",
            "is_wildcard": False,
        }

        with (
            patch("socket.create_connection", return_value=mock_sock),
            patch("ssl.create_default_context", return_value=mock_ctx),
            patch("app.scanners.tls._parse_cert_der", return_value=parsed),
        ):
            result = _fetch_cert_sync("x.com")

        assert result["cipher"] == ""

    def test_version_returns_none(self):
        """version() retourne None → protocol vide dans le résultat."""
        mock_sock = _make_mock_sock()
        mock_ssock = _make_mock_ssock()
        mock_ssock.version.return_value = None

        mock_ctx = MagicMock()
        mock_ctx.wrap_socket.return_value = mock_ssock

        parsed = {
            "not_after": datetime(2026, 12, 31, tzinfo=timezone.utc),
            "issuer_cn": "CA", "subject_cn": "x.com",
            "key_size": 2048, "key_type": "RSA", "sig_algo": "sha256",
            "is_wildcard": False,
        }

        with (
            patch("socket.create_connection", return_value=mock_sock),
            patch("ssl.create_default_context", return_value=mock_ctx),
            patch("app.scanners.tls._parse_cert_der", return_value=parsed),
        ):
            result = _fetch_cert_sync("x.com")

        assert result["protocol"] == ""

    def test_connection_refused_propagates(self):
        """socket.create_connection échoue → l'exception remonte."""
        with patch("socket.create_connection", side_effect=ConnectionRefusedError("refused")):
            with pytest.raises(ConnectionRefusedError):
                _fetch_cert_sync("down.example.com")

    def test_timeout_propagates(self):
        """socket.create_connection timeout → l'exception remonte."""
        with patch("socket.create_connection", side_effect=socket.timeout("timed out")):
            with pytest.raises(socket.timeout):
                _fetch_cert_sync("slow.example.com")

    def test_non_ssl_error_on_verify_true_propagates(self):
        """Une erreur non-SSL sur verify=True ne déclenche pas le fallback."""
        mock_sock = _make_mock_sock()
        mock_ctx = MagicMock()
        mock_ctx.wrap_socket.side_effect = OSError("Network unreachable")

        with (
            patch("socket.create_connection", return_value=mock_sock),
            patch("ssl.create_default_context", return_value=mock_ctx),
        ):
            with pytest.raises(OSError, match="Network unreachable"):
                _fetch_cert_sync("example.com")


# ===================================================================
# _parse_cert_der — parsing de certificat DER avec cryptography
# ===================================================================


def _generate_self_signed_der(
    cn="example.com",
    issuer_cn=None,
    sans=None,
    key_size=2048,
    use_ec=False,
    hash_algo=None,
):
    """Génère un vrai certificat DER auto-signé pour les tests."""
    from cryptography import x509
    from cryptography.x509.oid import NameOID
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa, ec

    if issuer_cn is None:
        issuer_cn = cn

    if use_ec:
        key = ec.generate_private_key(ec.SECP256R1())
    else:
        key = rsa.generate_private_key(public_exponent=65537, key_size=key_size)

    if hash_algo is None:
        hash_algo = hashes.SHA256()

    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, issuer_cn)])

    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime(2025, 1, 1, tzinfo=timezone.utc))
        .not_valid_after(datetime(2026, 12, 31, tzinfo=timezone.utc))
    )

    if sans is not None:
        builder = builder.add_extension(
            x509.SubjectAlternativeName([x509.DNSName(s) for s in sans]),
            critical=False,
        )

    cert = builder.sign(key, hash_algo)
    return cert.public_bytes(serialization.Encoding.DER)


class TestParseCertDer:
    def test_rsa_cert_basic_fields(self):
        """Parse un cert RSA avec CN, issuer, et date d'expiration."""
        der = _generate_self_signed_der(cn="test.com", key_size=2048)
        info = _parse_cert_der(der)

        assert info["subject_cn"] == "test.com"
        assert info["issuer_cn"] == "test.com"
        assert info["key_type"] == "RSA"
        assert info["key_size"] == 2048
        assert info["sig_algo"] == "sha256"
        assert info["not_after"] == datetime(2026, 12, 31, tzinfo=timezone.utc)
        assert info["is_wildcard"] is False

    def test_ec_cert_detected(self):
        """Parse un cert EC — key_type=EC, key_size=256."""
        der = _generate_self_signed_der(cn="ec.test.com", use_ec=True)
        info = _parse_cert_der(der)

        assert info["key_type"] == "EC"
        assert info["key_size"] == 256
        assert info["subject_cn"] == "ec.test.com"

    def test_rsa_4096(self):
        """Parse un cert RSA 4096 bits."""
        der = _generate_self_signed_der(cn="big.test.com", key_size=4096)
        info = _parse_cert_der(der)

        assert info["key_type"] == "RSA"
        assert info["key_size"] == 4096

    def test_wildcard_san_detected(self):
        """SAN avec *.example.com → is_wildcard=True."""
        der = _generate_self_signed_der(
            cn="example.com",
            sans=["example.com", "*.example.com"],
        )
        info = _parse_cert_der(der)

        assert info["is_wildcard"] is True

    def test_san_without_wildcard(self):
        """SAN sans wildcard → is_wildcard=False."""
        der = _generate_self_signed_der(
            cn="example.com",
            sans=["example.com", "www.example.com"],
        )
        info = _parse_cert_der(der)

        assert info["is_wildcard"] is False

    def test_no_san_extension(self):
        """Pas d'extension SAN → is_wildcard=False, pas d'erreur."""
        der = _generate_self_signed_der(cn="nosan.com", sans=None)
        info = _parse_cert_der(der)

        assert info["is_wildcard"] is False

    def test_different_issuer_and_subject(self):
        """Issuer != Subject → les deux CN sont correctement extraits."""
        der = _generate_self_signed_der(cn="site.com", issuer_cn="My CA")
        info = _parse_cert_der(der)

        assert info["subject_cn"] == "site.com"
        assert info["issuer_cn"] == "My CA"

    def test_sha1_signature_detected(self):
        """Certificat avec sig_algo SHA-1 — cryptography récent interdit SHA-1 pour signer,
        donc on mocke signature_hash_algorithm directement."""
        from cryptography.hazmat.primitives import hashes

        # Générer un cert normal, puis patcher l'attribut signature_hash_algorithm
        der = _generate_self_signed_der(cn="old.com")
        from cryptography import x509 as cx509

        real_cert = cx509.load_der_x509_certificate(der)

        with patch.object(type(real_cert), "signature_hash_algorithm", new_callable=lambda: property(lambda self: hashes.SHA1())):
            info = _parse_cert_der(der)

        assert "sha1" in info["sig_algo"].lower()

    def test_sha512_signature_detected(self):
        """Certificat signé avec SHA-512."""
        from cryptography.hazmat.primitives import hashes
        der = _generate_self_signed_der(cn="strong.com", hash_algo=hashes.SHA512())
        info = _parse_cert_der(der)

        assert "sha512" in info["sig_algo"].lower()

    def test_no_cn_in_subject(self):
        """Certificat sans CN dans le subject → subject_cn vide."""
        from cryptography import x509
        from cryptography.x509.oid import NameOID
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa

        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        # Subject sans CN — seulement Organization
        subject = x509.Name([x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Test Org")])
        issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Issuer CA")])

        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime(2025, 1, 1, tzinfo=timezone.utc))
            .not_valid_after(datetime(2026, 12, 31, tzinfo=timezone.utc))
            .sign(key, hashes.SHA256())
        )

        der = cert.public_bytes(serialization.Encoding.DER)
        info = _parse_cert_der(der)

        assert info["subject_cn"] == ""
        assert info["issuer_cn"] == "Issuer CA"

    def test_no_cn_in_issuer(self):
        """Certificat sans CN dans l'issuer → issuer_cn vide."""
        from cryptography import x509
        from cryptography.x509.oid import NameOID
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa

        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "my.site")])
        issuer = x509.Name([x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Org Only")])

        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime(2025, 1, 1, tzinfo=timezone.utc))
            .not_valid_after(datetime(2026, 12, 31, tzinfo=timezone.utc))
            .sign(key, hashes.SHA256())
        )

        der = cert.public_bytes(serialization.Encoding.DER)
        info = _parse_cert_der(der)

        assert info["subject_cn"] == "my.site"
        assert info["issuer_cn"] == ""


# ===================================================================
# _parse_cert_der — fallback sans cryptography
# ===================================================================


class TestParseCertDerFallback:
    def test_import_error_returns_safe_defaults(self):
        """Si cryptography n'est pas installé → fallback avec des valeurs vides."""
        with patch.dict("sys.modules", {"cryptography": None, "cryptography.x509": None}):
            # Force l'ImportError en patchant l'import dans la fonction
            import builtins
            original_import = builtins.__import__

            def fake_import(name, *args, **kwargs):
                if name.startswith("cryptography"):
                    raise ImportError("No module named 'cryptography'")
                return original_import(name, *args, **kwargs)

            with patch("builtins.__import__", side_effect=fake_import):
                info = _parse_cert_der(b"FAKE_DER_BYTES")

        assert info["issuer_cn"] == ""
        assert info["subject_cn"] == ""
        assert info["key_size"] is None
        assert info["key_type"] == ""
        assert info["sig_algo"] == ""
        assert info["is_wildcard"] is False
        # not_after est "now" — juste vérifier que c'est un datetime récent
        assert isinstance(info["not_after"], datetime)
        assert (datetime.now(timezone.utc) - info["not_after"]).total_seconds() < 5


# ===================================================================
# _get_cert_info — wrapper async
# ===================================================================


class TestGetCertInfo:
    async def test_delegates_to_fetch_cert_sync(self):
        """_get_cert_info appelle _fetch_cert_sync via run_in_executor."""
        expected = {"protocol": "TLSv1.3", "cipher": "AES256", "verified": True}

        with patch("app.scanners.tls._fetch_cert_sync", return_value=expected) as mock:
            result = await _get_cert_info("example.com")

        mock.assert_called_once_with("example.com")
        assert result == expected

    async def test_propagates_exception(self):
        """Les exceptions de _fetch_cert_sync remontent correctement."""
        with patch("app.scanners.tls._fetch_cert_sync", side_effect=ConnectionRefusedError("nope")):
            with pytest.raises(ConnectionRefusedError):
                await _get_cert_info("down.example.com")


# ===================================================================
# _check_wildcard_cert — détection de certificats wildcard
# ===================================================================


class TestCheckWildcardCert:
    def test_no_wildcard(self):
        """SANs sans wildcard → pas de finding."""
        findings = []
        _check_wildcard_cert({"sans": ["example.com", "www.example.com"]}, findings)
        assert len(findings) == 0

    def test_no_sans(self):
        """Pas de SANs → pas de finding."""
        findings = []
        _check_wildcard_cert({"sans": []}, findings)
        assert len(findings) == 0

    def test_normal_wildcard_medium(self):
        """Wildcard standard *.example.com → finding medium."""
        findings = []
        _check_wildcard_cert({"sans": ["*.example.com", "example.com"]}, findings)
        assert len(findings) == 1
        assert findings[0].severity == "medium"
        assert "wildcard" in findings[0].title.lower()

    def test_overly_broad_wildcard_high(self):
        """Wildcard sur TLD *.com → finding high (excessivement large)."""
        findings = []
        _check_wildcard_cert({"sans": ["*.com"]}, findings)
        assert len(findings) == 1
        assert findings[0].severity == "high"
        assert "large" in findings[0].title.lower() or "excessivement" in findings[0].title.lower()

    def test_multiple_wildcards(self):
        """Plusieurs wildcards → un seul finding medium."""
        findings = []
        _check_wildcard_cert({"sans": ["*.example.com", "*.api.example.com"]}, findings)
        assert len(findings) == 1
        assert findings[0].severity == "medium"

    def test_sans_key_missing(self):
        """Pas de clé 'sans' → pas de crash."""
        findings = []
        _check_wildcard_cert({}, findings)
        assert len(findings) == 0


# ===================================================================
# _check_san_coverage — domaine couvert par les SANs
# ===================================================================


class TestCheckSanCoverage:
    def test_domain_covered_by_exact_match(self):
        """Le domaine est dans les SANs → pas de finding."""
        findings = []
        _check_san_coverage({"sans": ["example.com", "www.example.com"]}, "example.com", findings)
        assert len(findings) == 0

    def test_domain_covered_by_wildcard(self):
        """Le domaine est couvert par un wildcard → pas de finding."""
        findings = []
        _check_san_coverage({"sans": ["*.example.com"]}, "www.example.com", findings)
        assert len(findings) == 0

    def test_domain_not_covered(self):
        """Le domaine n'est pas couvert → finding medium."""
        findings = []
        _check_san_coverage({"sans": ["other.com", "www.other.com"]}, "example.com", findings)
        assert len(findings) == 1
        assert findings[0].severity == "medium"
        assert "example.com" in findings[0].title

    def test_no_sans_at_all(self):
        """Pas de SANs → finding low."""
        findings = []
        _check_san_coverage({"sans": []}, "example.com", findings)
        assert len(findings) == 1
        assert findings[0].severity == "low"
        assert "SAN" in findings[0].title

    def test_sans_key_missing(self):
        """Pas de clé 'sans' → finding low (traité comme vide)."""
        findings = []
        _check_san_coverage({}, "example.com", findings)
        assert len(findings) == 1
        assert findings[0].severity == "low"
