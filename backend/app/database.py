import os
from collections.abc import AsyncGenerator

from sqlalchemy.ext.asyncio import (
    create_async_engine,
    async_sessionmaker,
    AsyncSession,
    AsyncConnection,
)
from sqlalchemy.orm import DeclarativeBase

DATABASE_URL = os.getenv("DATABASE_URL", "sqlite+aiosqlite:////data/ssc.db")

engine = create_async_engine(DATABASE_URL, echo=False)
AsyncSessionLocal = async_sessionmaker(engine, expire_on_commit=False)


class Base(DeclarativeBase):
    pass


async def get_db() -> AsyncGenerator[AsyncSession, None]:
    async with AsyncSessionLocal() as session:
        yield session


async def _ensure_scan_module_unique_index(conn: AsyncConnection) -> None:
    """Backfill the ``(scan_id, name)`` unique index on pre-existing databases.

    The schema is built with ``create_all`` and there is no migration tool, so
    on a persistent volume ``create_all`` leaves an already-existing
    ``scan_modules`` table on its old schema after an upgrade — it never adds the
    unique index introduced for the constraint. The orchestrator relies on
    ``INSERT ... ON CONFLICT (scan_id, name) DO NOTHING``, which SQLite only
    accepts when a matching unique index exists; without this backfill every scan
    and rescan would fail on already-deployed databases.

    Detection is by columns, not by index name: a fresh database created by
    ``create_all`` already carries the constraint's auto-index, so we must not add
    a second, redundant one (which would make ``ON CONFLICT`` ambiguous). When the
    index is missing we first drop any duplicate ``(scan_id, name)`` rows a
    pre-constraint database may hold — and their findings, since SQLite does not
    enforce the cascade unless foreign keys are enabled — otherwise the
    ``CREATE UNIQUE INDEX`` itself would fail. The surviving row keeps the scan's
    results intact.
    """
    index_list = (
        await conn.exec_driver_sql("PRAGMA index_list('scan_modules')")
    ).fetchall()
    for index in index_list:
        # PRAGMA index_list columns: (seq, name, unique, origin, partial).
        index_name, is_unique = index[1], index[2]
        if not is_unique:
            continue
        columns = (
            await conn.exec_driver_sql(f"PRAGMA index_info('{index_name}')")
        ).fetchall()
        # PRAGMA index_info columns: (seqno, cid, name).
        if [column[2] for column in columns] == ["scan_id", "name"]:
            return  # A unique index over (scan_id, name) already exists.

    await conn.exec_driver_sql(
        """
        DELETE FROM findings
        WHERE module_id IN (
            SELECT id FROM scan_modules
            WHERE rowid NOT IN (
                SELECT MIN(rowid) FROM scan_modules GROUP BY scan_id, name
            )
        )
        """
    )
    await conn.exec_driver_sql(
        """
        DELETE FROM scan_modules
        WHERE rowid NOT IN (
            SELECT MIN(rowid) FROM scan_modules GROUP BY scan_id, name
        )
        """
    )
    await conn.exec_driver_sql(
        "CREATE UNIQUE INDEX uq_scan_module_scan_id_name "
        "ON scan_modules (scan_id, name)"
    )


async def init_db():
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
        await _ensure_scan_module_unique_index(conn)
