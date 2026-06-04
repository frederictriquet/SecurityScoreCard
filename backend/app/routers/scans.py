from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks, Request
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from sqlalchemy.orm import selectinload

from app.database import get_db
from app.limiter import limiter
from app.models import Scan, ScanModule, now_utc
from app.schemas import ScanCreate, ScanOut, ScanSummary
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
    # Domaine homographe (IDN spoofing) techniquement valide : on NE lance PAS le
    # scan tout de suite. Tant que l'utilisateur n'a pas confirmé explicitement,
    # on renvoie une réponse dédiée expliquant le danger, la forme visible saisie
    # et la forme Punycode réelle qui serait scannée. Aucun Scan n'est créé.
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


@router.get("/{scan_id}", response_model=ScanOut)
async def get_scan(scan_id: str, db: AsyncSession = Depends(get_db)):
    result = await db.execute(
        select(Scan).options(SCAN_WITH_MODULES).where(Scan.id == scan_id)
    )
    scan = result.scalar_one_or_none()
    if scan is None:
        raise HTTPException(status_code=404, detail="Scan introuvable")
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
        raise HTTPException(status_code=404, detail="Scan introuvable")

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
        raise HTTPException(status_code=404, detail="Scan introuvable")
    await db.delete(scan)
    await db.commit()
