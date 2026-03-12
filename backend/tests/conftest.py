"""Fixtures partagées pour la suite de tests SecurityScoreCard."""

import os
import tempfile

# Créer un fichier SQLite temporaire pour les tests.
# SQLite in-memory + StaticPool ne supporte pas les sessions concurrentes
# (asyncio.gather dans l'orchestrateur), donc on utilise un vrai fichier.
_test_db = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
_test_db.close()
os.environ["DATABASE_URL"] = f"sqlite+aiosqlite:///{_test_db.name}"

import pytest
from unittest.mock import AsyncMock

import dns.asyncresolver
import dns.resolver
import dns.name

# Re-créer l'engine APRÈS avoir défini DATABASE_URL
import app.database as _db

_db.engine = _db.create_async_engine(_db.DATABASE_URL, echo=False)
_db.AsyncSessionLocal = _db.async_sessionmaker(_db.engine, expire_on_commit=False)

# L'orchestrateur importe AsyncSessionLocal au top-level : patcher la référence
from app.scanners import orchestrator as _orch

_orch.AsyncSessionLocal = _db.AsyncSessionLocal


# ---------------------------------------------------------------------------
# DNS resolver mock
# ---------------------------------------------------------------------------


class FakeDnsAnswer:
    """Simule une réponse dns.resolver contenant des records TXT/MX/etc."""

    def __init__(self, records: list):
        self._records = records

    def __iter__(self):
        return iter(self._records)

    def __bool__(self):
        return bool(self._records)

    def __len__(self):
        return len(self._records)

    def __getitem__(self, index):
        return self._records[index]


class FakeTxtRecord:
    def __init__(self, text: str):
        self._text = text

    def to_text(self) -> str:
        return self._text


class FakeMxRecord:
    def __init__(self, exchange: str, preference: int = 10):
        self.exchange = dns.name.from_text(exchange)
        self.preference = preference


@pytest.fixture
def mock_resolver():
    """Retourne un AsyncMock configuré comme un dns.asyncresolver.Resolver."""
    resolver = AsyncMock(spec=dns.asyncresolver.Resolver)
    resolver.nameservers = ["8.8.8.8", "1.1.1.1"]
    return resolver


# ---------------------------------------------------------------------------
# Helpers pour construire des cert_info (TLS)
# ---------------------------------------------------------------------------


def make_cert_info(
    *,
    not_after=None,
    issuer_cn="Let's Encrypt Authority X3",
    subject_cn="example.com",
    key_type="RSA",
    key_size=2048,
    sig_algo="sha256",
    protocol="TLSv1.3",
    cipher="TLS_AES_256_GCM_SHA384",
    verified=True,
    is_wildcard=False,
    sans=None,
):
    from datetime import datetime, timezone, timedelta

    if not_after is None:
        not_after = datetime.now(timezone.utc) + timedelta(days=90)
    if sans is None:
        sans = ["example.com", "www.example.com"]
    return {
        "not_after": not_after,
        "issuer_cn": issuer_cn,
        "subject_cn": subject_cn,
        "key_type": key_type,
        "key_size": key_size,
        "sig_algo": sig_algo,
        "protocol": protocol,
        "cipher": cipher,
        "verified": verified,
        "is_wildcard": is_wildcard,
        "sans": sans,
    }
