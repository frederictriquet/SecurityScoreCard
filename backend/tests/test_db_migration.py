"""Tests for the in-place upgrade migration in app.database.

Regression guard for the production upgrade path: the database lives on a
persistent volume and the schema is built with ``create_all`` (no Alembic), so
an already-existing ``scan_modules`` table keeps its old schema after an
upgrade. The orchestrator's ``INSERT ... ON CONFLICT (scan_id, name)`` requires a
matching unique index, which SQLite rejects on the old schema with
``OperationalError: ON CONFLICT clause does not match any PRIMARY KEY or UNIQUE
constraint``. ``init_db`` must backfill that index on existing databases so every
new scan and rescan keeps working after the release.
"""

import os
import tempfile

import pytest
from sqlalchemy.dialects.sqlite import insert as sqlite_insert
from sqlalchemy.exc import OperationalError

import app.database as _db
from app.models import ScanModule


# Old schema: ``scan_modules`` without the (scan_id, name) unique index, exactly
# as databases created before the constraint was introduced look on disk.
_OLD_SCHEMA = [
    """
    CREATE TABLE scans (
        id TEXT PRIMARY KEY,
        domain TEXT NOT NULL,
        status TEXT,
        score INTEGER,
        grade TEXT,
        started_at TIMESTAMP,
        completed_at TIMESTAMP,
        created_at TIMESTAMP
    )
    """,
    """
    CREATE TABLE scan_modules (
        id TEXT PRIMARY KEY,
        scan_id TEXT NOT NULL,
        name TEXT NOT NULL,
        status TEXT,
        score INTEGER,
        weight FLOAT NOT NULL,
        started_at TIMESTAMP,
        completed_at TIMESTAMP
    )
    """,
    """
    CREATE TABLE findings (
        id TEXT PRIMARY KEY,
        module_id TEXT NOT NULL,
        severity TEXT NOT NULL,
        title TEXT NOT NULL,
        description TEXT NOT NULL,
        remediation TEXT,
        raw_data TEXT
    )
    """,
]


@pytest.fixture
async def legacy_db():
    """Build an old-schema database (no unique index) with duplicate modules.

    Yields the engine pointed at a real file, with ``app.database`` globals
    swapped to it so ``init_db`` runs the migration against this database.
    """
    db_file = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
    db_file.close()
    url = f"sqlite+aiosqlite:///{db_file.name}"

    engine = _db.create_async_engine(url, echo=False)
    saved_engine, saved_factory = _db.engine, _db.AsyncSessionLocal
    _db.engine = engine
    _db.AsyncSessionLocal = _db.async_sessionmaker(engine, expire_on_commit=False)

    async with engine.begin() as conn:
        for stmt in _OLD_SCHEMA:
            await conn.exec_driver_sql(stmt)
        # One scan with a DUPLICATE (scan_id, "dns") module — the exact state an
        # overlapping rescan could leave behind before the constraint existed.
        await conn.exec_driver_sql(
            "INSERT INTO scans (id, domain, status) VALUES ('s1', 'example.com', 'completed')"
        )
        await conn.exec_driver_sql(
            "INSERT INTO scan_modules (id, scan_id, name, status, score, weight) "
            "VALUES ('m1', 's1', 'dns', 'completed', 80, 1.0)"
        )
        await conn.exec_driver_sql(
            "INSERT INTO scan_modules (id, scan_id, name, status, score, weight) "
            "VALUES ('m2', 's1', 'dns', 'completed', 80, 1.0)"
        )
        await conn.exec_driver_sql(
            "INSERT INTO findings (id, module_id, severity, title, description) "
            "VALUES ('f1', 'm1', 'high', 'Kept', 'survivor')"
        )
        await conn.exec_driver_sql(
            "INSERT INTO findings (id, module_id, severity, title, description) "
            "VALUES ('f2', 'm2', 'high', 'Dropped', 'duplicate')"
        )

    try:
        yield engine
    finally:
        await engine.dispose()
        _db.engine, _db.AsyncSessionLocal = saved_engine, saved_factory
        os.unlink(db_file.name)


async def _on_conflict_insert(engine, scan_id: str, name: str) -> None:
    """Run the orchestrator's idempotent module INSERT (the path that crashes
    on the un-migrated old schema)."""
    async with engine.begin() as conn:
        await conn.execute(
            sqlite_insert(ScanModule)
            .values(scan_id=scan_id, name=name, weight=1.0, status="pending")
            .on_conflict_do_nothing(index_elements=["scan_id", "name"])
        )


class TestUnexpectedOldSchema:
    async def test_on_conflict_fails_without_migration(self, legacy_db):
        """Documents the bug: ON CONFLICT raises on the un-migrated old schema."""
        with pytest.raises(OperationalError):
            await _on_conflict_insert(legacy_db, "s1", "dns")


class TestInitDbMigratesLegacySchema:
    async def test_init_db_backfills_unique_index(self, legacy_db):
        await _db.init_db()

        async with legacy_db.connect() as conn:
            indexes = (
                await conn.exec_driver_sql("PRAGMA index_list('scan_modules')")
            ).fetchall()
            unique_over_scan_name = []
            for index in indexes:
                if not index[2]:  # unique flag
                    continue
                cols = (
                    await conn.exec_driver_sql(
                        f"PRAGMA index_info('{index[1]}')"
                    )
                ).fetchall()
                if [c[2] for c in cols] == ["scan_id", "name"]:
                    unique_over_scan_name.append(index[1])

        # Exactly one unique index over (scan_id, name): the migration must not
        # leave the ON CONFLICT target ambiguous.
        assert len(unique_over_scan_name) == 1

    async def test_init_db_collapses_duplicate_modules(self, legacy_db):
        await _db.init_db()

        async with legacy_db.connect() as conn:
            module_count = (
                await conn.exec_driver_sql(
                    "SELECT COUNT(*) FROM scan_modules WHERE scan_id='s1' AND name='dns'"
                )
            ).scalar()
            # The surviving module keeps its findings; the duplicate's are gone.
            kept = (
                await conn.exec_driver_sql(
                    "SELECT title FROM findings ORDER BY title"
                )
            ).fetchall()

        assert module_count == 1
        assert [row[0] for row in kept] == ["Kept"]

    async def test_on_conflict_insert_works_after_migration(self, legacy_db):
        """The core regression: the orchestrator's ON CONFLICT path must run
        after the migration instead of raising OperationalError."""
        await _db.init_db()

        # Inserting the already-present (s1, dns) module is a no-op, not a crash.
        await _on_conflict_insert(legacy_db, "s1", "dns")
        # A brand-new (scan_id, name) still inserts normally.
        await _on_conflict_insert(legacy_db, "s1", "tls")

        async with legacy_db.connect() as conn:
            dns_count = (
                await conn.exec_driver_sql(
                    "SELECT COUNT(*) FROM scan_modules WHERE scan_id='s1' AND name='dns'"
                )
            ).scalar()
            tls_count = (
                await conn.exec_driver_sql(
                    "SELECT COUNT(*) FROM scan_modules WHERE scan_id='s1' AND name='tls'"
                )
            ).scalar()

        assert dns_count == 1
        assert tls_count == 1

    async def test_migration_is_idempotent(self, legacy_db):
        """Running init_db twice must not add a second index or fail."""
        await _db.init_db()
        await _db.init_db()  # second run sees the index and returns early

        async with legacy_db.connect() as conn:
            indexes = (
                await conn.exec_driver_sql("PRAGMA index_list('scan_modules')")
            ).fetchall()
            unique_over_scan_name = 0
            for index in indexes:
                if not index[2]:
                    continue
                cols = (
                    await conn.exec_driver_sql(
                        f"PRAGMA index_info('{index[1]}')"
                    )
                ).fetchall()
                if [c[2] for c in cols] == ["scan_id", "name"]:
                    unique_over_scan_name += 1

        assert unique_over_scan_name == 1


class TestInitDbFreshDatabase:
    async def test_fresh_db_has_single_unique_index(self):
        """A brand-new database created by init_db must carry exactly one unique
        index over (scan_id, name) — create_all's auto-index — and the migration
        must not add a redundant second one."""
        db_file = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        db_file.close()
        url = f"sqlite+aiosqlite:///{db_file.name}"
        engine = _db.create_async_engine(url, echo=False)
        saved_engine, saved_factory = _db.engine, _db.AsyncSessionLocal
        _db.engine = engine
        _db.AsyncSessionLocal = _db.async_sessionmaker(engine, expire_on_commit=False)

        try:
            await _db.init_db()

            async with engine.connect() as conn:
                indexes = (
                    await conn.exec_driver_sql("PRAGMA index_list('scan_modules')")
                ).fetchall()
                unique_over_scan_name = 0
                for index in indexes:
                    if not index[2]:
                        continue
                    cols = (
                        await conn.exec_driver_sql(
                            f"PRAGMA index_info('{index[1]}')"
                        )
                    ).fetchall()
                    if [c[2] for c in cols] == ["scan_id", "name"]:
                        unique_over_scan_name += 1

            assert unique_over_scan_name == 1
            # And the ON CONFLICT path works out of the box on a fresh DB.
            await _on_conflict_insert(engine, "fresh", "dns")
            await _on_conflict_insert(engine, "fresh", "dns")
            async with engine.connect() as conn:
                count = (
                    await conn.exec_driver_sql(
                        "SELECT COUNT(*) FROM scan_modules WHERE scan_id='fresh'"
                    )
                ).scalar()
            assert count == 1
        finally:
            await engine.dispose()
            _db.engine, _db.AsyncSessionLocal = saved_engine, saved_factory
            os.unlink(db_file.name)
