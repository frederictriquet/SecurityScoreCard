from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks, Request
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, update
from sqlalchemy.orm import selectinload

from app.database import get_db
from app.limiter import limiter
from app.models import Scan, ScanModule, now_utc
from app.schemas import (
    ScanCreate,
    ScanOut,
    ScanSummary,
    ScanComparison,
    FindingRef,
)
from app.scanners.orchestrator import run_scan

router = APIRouter(prefix="/api/scans", tags=["scans"])

SCAN_WITH_MODULES = (
    selectinload(Scan.modules).selectinload(ScanModule.findings)
)


@router.post("", response_model=ScanOut, status_code=201)
@limiter.limit("5/minute")
async def create_scan(
    request: Request,
    body: ScanCreate,
    background_tasks: BackgroundTasks,
    db: AsyncSession = Depends(get_db),
):
    # Technically valid homograph domain (IDN spoofing): we do NOT launch the
    # scan right away. Until the user has explicitly confirmed, we return a
    # dedicated response explaining the danger, the visible form entered and the
    # real Punycode form that would be scanned. No Scan is created.
    if body.homograph_explanation and not body.confirm:
        raise HTTPException(
            status_code=409,
            detail={
                "needs_confirmation": True,
                "explanation": body.homograph_explanation,
                "domain": body.visible_domain,
                "punycode": body.domain,
            },
        )

    scan = Scan(domain=body.domain)
    db.add(scan)
    await db.commit()

    background_tasks.add_task(run_scan, scan.id, body.domain)

    result = await db.execute(
        select(Scan).options(SCAN_WITH_MODULES).where(Scan.id == scan.id)
    )
    return result.scalar_one()


@router.get("", response_model=list[ScanSummary])
async def list_scans(db: AsyncSession = Depends(get_db)):
    result = await db.execute(
        select(Scan).order_by(Scan.created_at.desc()).limit(50)
    )
    return result.scalars().all()


@router.get("/history", response_model=list[ScanSummary])
async def scan_history(domain: str, db: AsyncSession = Depends(get_db)):
    """Past scans of a single domain, most recent first.

    Powers the historical comparison view: the evolution of a domain's score
    over time. An unknown domain simply yields an empty list.
    """
    result = await db.execute(
        select(Scan)
        .where(Scan.domain == domain)
        .order_by(Scan.created_at.desc())
        .limit(50)
    )
    return result.scalars().all()


def _finding_refs(scan: Scan) -> dict[tuple[str, str], FindingRef]:
    """Index a scan's findings by their stable identity ``(module, title)``."""
    refs: dict[tuple[str, str], FindingRef] = {}
    for module in scan.modules:
        for finding in module.findings:
            key = (module.name, finding.title)
            # Keep the first occurrence: the (module, title) pair is the stable
            # identity, duplicates collapse to a single reference.
            refs.setdefault(
                key,
                FindingRef(
                    module=module.name,
                    severity=finding.severity,
                    title=finding.title,
                ),
            )
    return refs


@router.get("/{scan_id}/diff", response_model=ScanComparison)
async def scan_diff(
    scan_id: str,
    against: str | None = None,
    db: AsyncSession = Depends(get_db),
):
    """Diff a scan against the previous scan of the same domain.

    By default compares with the immediately preceding scan of the domain; pass
    ``against=<scan_id>`` to compare with a specific earlier scan. Reports the
    findings that appeared (new) and disappeared (resolved), and the score/grade
    variation. With no previous scan, the diff is empty and the deltas absent.
    """
    result = await db.execute(
        select(Scan).options(SCAN_WITH_MODULES).where(Scan.id == scan_id)
    )
    scan = result.scalar_one_or_none()
    if scan is None:
        raise HTTPException(status_code=404, detail="Scan not found")

    if against is not None:
        result = await db.execute(
            select(Scan).options(SCAN_WITH_MODULES).where(Scan.id == against)
        )
        previous = result.scalar_one_or_none()
        if previous is None:
            raise HTTPException(status_code=404, detail="Comparison scan not found")
    else:
        result = await db.execute(
            select(Scan)
            .options(SCAN_WITH_MODULES)
            .where(
                Scan.domain == scan.domain,
                Scan.created_at < scan.created_at,
            )
            .order_by(Scan.created_at.desc())
            .limit(1)
        )
        previous = result.scalar_one_or_none()

    if previous is None:
        # Single scan / no earlier scan: nothing to compare against.
        return ScanComparison(scan_id=scan.id)

    current_refs = _finding_refs(scan)
    previous_refs = _finding_refs(previous)

    new_findings = [
        ref for key, ref in current_refs.items() if key not in previous_refs
    ]
    resolved_findings = [
        ref for key, ref in previous_refs.items() if key not in current_refs
    ]

    score_delta = (
        scan.score - previous.score
        if scan.score is not None and previous.score is not None
        else None
    )
    grade_change = (
        f"{previous.grade}->{scan.grade}"
        if scan.grade is not None
        and previous.grade is not None
        and scan.grade != previous.grade
        else None
    )

    return ScanComparison(
        scan_id=scan.id,
        previous_scan=ScanSummary.model_validate(previous),
        score_delta=score_delta,
        grade_change=grade_change,
        new_findings=new_findings,
        resolved_findings=resolved_findings,
    )


@router.get("/{scan_id}", response_model=ScanOut)
async def get_scan(scan_id: str, db: AsyncSession = Depends(get_db)):
    result = await db.execute(
        select(Scan).options(SCAN_WITH_MODULES).where(Scan.id == scan_id)
    )
    scan = result.scalar_one_or_none()
    if scan is None:
        raise HTTPException(status_code=404, detail="Scan not found")
    return scan


@router.post("/{scan_id}/rescan", response_model=ScanOut)
@limiter.limit("5/minute")
async def rescan_in_place(
    scan_id: str,
    request: Request,
    background_tasks: BackgroundTasks,
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(
        select(Scan).options(SCAN_WITH_MODULES).where(Scan.id == scan_id)
    )
    scan = result.scalar_one_or_none()
    if scan is None:
        raise HTTPException(status_code=404, detail="Scan not found")

    # Serialize rescans per scan. Claim the scan with an atomic compare-and-swap:
    # the UPDATE only matches when the scan is in a terminal state, so a rescan
    # arriving while a scan or rescan of the same id is still pending or running
    # loses the claim. This removes the race where a second rescan deleted the
    # modules out from under the first run's in-flight scanners (which raised
    # SQLAlchemy StaleDataError). Only the claim winner deletes and recreates the
    # modules and findings, so the per-module work is never concurrent.
    claim = await db.execute(
        update(Scan)
        .where(Scan.id == scan_id, Scan.status.in_(("completed", "failed")))
        .values(status="pending")
    )
    if claim.rowcount == 0:
        await db.rollback()
        raise HTTPException(
            status_code=409,
            detail="A scan is already in progress for this resource",
        )

    # We now exclusively own the scan: drop the previous run's modules (their
    # findings cascade) and reset the scan's result fields before re-running.
    for module in scan.modules:
        await db.delete(module)

    scan.status = "pending"
    scan.score = None
    scan.grade = None
    scan.started_at = None
    scan.completed_at = None
    scan.created_at = now_utc()

    await db.commit()

    background_tasks.add_task(run_scan, scan.id, scan.domain)

    result = await db.execute(
        select(Scan).options(SCAN_WITH_MODULES).where(Scan.id == scan.id)
    )
    return result.scalar_one()


@router.delete("/{scan_id}", status_code=204)
async def delete_scan(scan_id: str, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(Scan).where(Scan.id == scan_id))
    scan = result.scalar_one_or_none()
    if scan is None:
        raise HTTPException(status_code=404, detail="Scan not found")
    await db.delete(scan)
    await db.commit()
