"""Shared fixtures for the SecurityScoreCard test suite."""

import os
import tempfile

# Create a temporary SQLite file for the tests.
# In-memory SQLite + StaticPool does not support concurrent sessions
# (asyncio.gather in the orchestrator), so we use a real file.
_test_db = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
_test_db.close()
os.environ["DATABASE_URL"] = f"sqlite+aiosqlite:///{_test_db.name}"

import pytest
from unittest.mock import AsyncMock

import dns.asyncresolver
import dns.resolver
import dns.name

# Re-create the engine AFTER setting DATABASE_URL
import app.database as _db

_db.engine = _db.create_async_engine(_db.DATABASE_URL, echo=False)
_db.AsyncSessionLocal = _db.async_sessionmaker(_db.engine, expire_on_commit=False)

# The orchestrator imports AsyncSessionLocal at the top level: patch the reference
from app.scanners import orchestrator as _orch

_orch.AsyncSessionLocal = _db.AsyncSessionLocal


# ---------------------------------------------------------------------------
# Per-test database isolation
# ---------------------------------------------------------------------------


@pytest.fixture
async def isolated_db():
    """Give every test a private SQLite file and a fresh async engine.

    ``asyncio_mode = auto`` runs each test inside its own event loop. A single
    async engine shared across those loops corrupts aiosqlite's connection pool:
    connections (and their pending state) get bound to the loop that created
    them, so state bleeds between tests — manifesting as "database is locked",
    wrong row counts ("assert 1 == 7") or a stray module named "s".

    To stay reliable we build the engine — and dispose it — *inside* the test's
    own event loop, backed by a database file unique to that test, then point
    every module-level reference (``app.database`` globals consumed by
    ``get_db`` and the orchestrator's imported ``AsyncSessionLocal``) at it.
    """
    db_file = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
    db_file.close()
    url = f"sqlite+aiosqlite:///{db_file.name}"

    engine = _db.create_async_engine(url, echo=False)
    session_factory = _db.async_sessionmaker(engine, expire_on_commit=False)

    _db.engine = engine
    _db.AsyncSessionLocal = session_factory
    _orch.AsyncSessionLocal = session_factory

    async with engine.begin() as conn:
        await conn.run_sync(_db.Base.metadata.create_all)

    try:
        yield session_factory
    finally:
        await engine.dispose()
        os.unlink(db_file.name)


# ---------------------------------------------------------------------------
# DNS resolver mock
# ---------------------------------------------------------------------------


class FakeDnsAnswer:
    """Simulate a dns.resolver answer containing TXT/MX/etc. records."""

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
    """Return an AsyncMock configured like a dns.asyncresolver.Resolver."""
    resolver = AsyncMock(spec=dns.asyncresolver.Resolver)
    resolver.nameservers = ["8.8.8.8", "1.1.1.1"]
    return resolver


# ---------------------------------------------------------------------------
# Helpers to build cert_info (TLS)
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
