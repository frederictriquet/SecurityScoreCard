import asyncio
from datetime import datetime, timezone

from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.models import Scan, ScanModule, Finding
from app.scanners.base import BaseScanner
from app.scanners.dns import DnsScanner
from app.scanners.tls import TlsScanner
from app.scanners.headers import HeadersScanner
from app.scanners.reputation import ReputationScanner
from app.scanners.subdomains import SubdomainsScanner
from app.scanners.leaks import LeaksScanner

SCANNERS: list[BaseScanner] = [
    DnsScanner(),
    TlsScanner(),
    HeadersScanner(),
    ReputationScanner(),
    SubdomainsScanner(),
    LeaksScanner(),
]

GRADES = [(90, "A"), (80, "B"), (70, "C"), (60, "D"), (0, "F")]


def score_to_grade(score: int) -> str:
    for threshold, grade in GRADES:
        if score >= threshold:
            return grade
    return "F"


async def run_single_scanner(
    scanner: BaseScanner,
    domain: str,
    scan_id: str,
    session: AsyncSession,
) -> None:
    stmt = select(ScanModule).where(
        ScanModule.scan_id == scan_id,
        ScanModule.name == scanner.name,
    )
    result = await session.execute(stmt)
    module = result.scalar_one()

    module.status = "running"
    module.started_at = datetime.now(timezone.utc)
    await session.commit()

    try:
        scan_result = await scanner.scan(domain)

        for f in scan_result.findings:
            finding = Finding(
                module_id=module.id,
                severity=f.severity,
                title=f.title,
                description=f.description,
                remediation=f.remediation,
                raw_data=f.raw_data,
            )
            session.add(finding)

        module.score = scan_result.score
        module.status = "completed"
    except Exception as exc:
        module.status = "failed"
        module.score = 0
        session.add(Finding(
            module_id=module.id,
            severity="info",
            title="Scan échoué",
            description=str(exc),
        ))

    module.completed_at = datetime.now(timezone.utc)
    await session.commit()


async def run_scan(scan_id: str, domain: str, session: AsyncSession) -> None:
    stmt = select(Scan).where(Scan.id == scan_id)
    result = await session.execute(stmt)
    scan = result.scalar_one()

    scan.status = "running"
    scan.started_at = datetime.now(timezone.utc)

    for scanner in SCANNERS:
        module = ScanModule(
            scan_id=scan_id,
            name=scanner.name,
            weight=scanner.weight,
            status="pending",
        )
        session.add(module)

    await session.commit()

    await asyncio.gather(*[
        run_single_scanner(scanner, domain, scan_id, session)
        for scanner in SCANNERS
    ])

    stmt = select(ScanModule).where(ScanModule.scan_id == scan_id)
    result = await session.execute(stmt)
    modules = result.scalars().all()

    total_weight = sum(m.weight for m in modules if m.score is not None)
    if total_weight > 0:
        weighted_sum = sum((m.score or 0) * m.weight for m in modules)
        global_score = round(weighted_sum / total_weight)
    else:
        global_score = 0

    scan.score = global_score
    scan.grade = score_to_grade(global_score)
    scan.status = "completed"
    scan.completed_at = datetime.now(timezone.utc)
    await session.commit()
