import asyncio
from datetime import datetime, timezone

from sqlalchemy import select, delete, update
from sqlalchemy.dialects.sqlite import insert as sqlite_insert

from app.database import AsyncSessionLocal
from app.models import Scan, ScanModule, Finding
from app.scanners.base import BaseScanner
from app.scanners.dns import DnsScanner
from app.scanners.tls import TlsScanner
from app.scanners.headers import HeadersScanner
from app.scanners.reputation import ReputationScanner
from app.scanners.subdomains import SubdomainsScanner
from app.scanners.leaks import LeaksScanner
from app.scanners.ports import PortsScanner

SCANNERS: list[BaseScanner] = [
    DnsScanner(),
    TlsScanner(),
    HeadersScanner(),
    ReputationScanner(),
    SubdomainsScanner(),
    LeaksScanner(),
    PortsScanner(),
]

GRADES = [(90, "A"), (80, "B"), (70, "C"), (60, "D"), (0, "F")]


def score_to_grade(score: int) -> str:
    for threshold, grade in GRADES:
        if score >= threshold:
            return grade
    return "F"


async def run_single_scanner(scanner: BaseScanner, domain: str, scan_id: str) -> None:
    """Each scanner runs in its own session to avoid concurrency issues.

    Overlapping rescans of the same scan spawn two runners for the same
    ``(scan_id, name)`` module. We claim the module with an atomic
    compare-and-swap: only the runner that flips the status from a non-running
    state to ``"running"`` proceeds; any concurrent runner that loses the claim
    returns. SQLite serializes writers, so exactly one runner wins. This makes
    the delete-findings/run-scanner/insert-findings sequence run for a single
    runner at a time, so an overlapping rescan can no longer interleave two
    inserts and persist duplicated findings.
    """
    async with AsyncSessionLocal() as session:
        started_at = datetime.now(timezone.utc)
        claim = await session.execute(
            update(ScanModule)
            .where(
                ScanModule.scan_id == scan_id,
                ScanModule.name == scanner.name,
                ScanModule.status != "running",
            )
            .values(status="running", started_at=started_at)
        )
        await session.commit()

        # rowcount == 0 means another runner already owns this module, or a
        # concurrent rescan deleted it: there is nothing to run here.
        if claim.rowcount == 0:
            return

        result = await session.execute(
            select(ScanModule).where(
                ScanModule.scan_id == scan_id,
                ScanModule.name == scanner.name,
            )
        )
        # (scan_id, name) is unique, so this matches at most one module. A
        # concurrent rescan may have deleted it after the claim committed.
        module = result.scalar_one_or_none()
        if module is None:
            return

        # Drop findings left by a previous run of this module so a rescan replaces
        # them instead of accumulating duplicates.
        await session.execute(delete(Finding).where(Finding.module_id == module.id))
        await session.commit()

        try:
            scan_result = await scanner.scan(domain)

            for f in scan_result.findings:
                session.add(Finding(
                    module_id=module.id,
                    severity=f.severity,
                    title=f.title,
                    description=f.description,
                    remediation=f.remediation,
                    raw_data=f.raw_data,
                ))

            module.score = scan_result.score
            module.status = "completed"
        except Exception as exc:
            module.status = "failed"
            module.score = 0
            session.add(Finding(
                module_id=module.id,
                severity="info",
                title="Scan failed",
                description=str(exc),
            ))

        module.completed_at = datetime.now(timezone.utc)
        await session.commit()


async def run_scan(scan_id: str, domain: str) -> None:
    # Initialize the scan and create the modules
    async with AsyncSessionLocal() as session:
        result = await session.execute(select(Scan).where(Scan.id == scan_id))
        scan = result.scalar_one()

        scan.status = "running"
        scan.started_at = datetime.now(timezone.utc)

        # Create one module per scanner idempotently. A concurrent rescan may be
        # recreating the same (scan_id, name) rows at the same time; the unique
        # constraint turns the duplicate INSERT into a no-op instead of letting
        # both runs succeed and leave duplicated modules behind.
        for scanner in SCANNERS:
            await session.execute(
                sqlite_insert(ScanModule)
                .values(
                    scan_id=scan_id,
                    name=scanner.name,
                    weight=scanner.weight,
                    status="pending",
                )
                .on_conflict_do_nothing(index_elements=["scan_id", "name"])
            )

        await session.commit()

    # Run all scanners in parallel, each with its own session
    await asyncio.gather(*[
        run_single_scanner(scanner, domain, scan_id)
        for scanner in SCANNERS
    ])

    # Compute the global score
    async with AsyncSessionLocal() as session:
        result = await session.execute(
            select(ScanModule).where(ScanModule.scan_id == scan_id)
        )
        modules = result.scalars().all()

        total_weight = sum(m.weight for m in modules if m.score is not None)
        global_score = round(
            sum((m.score or 0) * m.weight for m in modules) / total_weight
        ) if total_weight > 0 else 0

        result = await session.execute(select(Scan).where(Scan.id == scan_id))
        scan = result.scalar_one()
        scan.score = global_score
        scan.grade = score_to_grade(global_score)
        scan.status = "completed"
        scan.completed_at = datetime.now(timezone.utc)
        await session.commit()
