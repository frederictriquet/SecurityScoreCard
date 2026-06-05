import uuid
from datetime import datetime, timezone
from sqlalchemy import String, Integer, Float, DateTime, ForeignKey, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship
from app.database import Base


def now_utc() -> datetime:
    return datetime.now(timezone.utc)


def new_uuid() -> str:
    return str(uuid.uuid4())


class Scan(Base):
    __tablename__ = "scans"

    id: Mapped[str] = mapped_column(String, primary_key=True, default=new_uuid)
    domain: Mapped[str] = mapped_column(String, nullable=False, index=True)
    status: Mapped[str] = mapped_column(String, default="pending")  # pending | running | completed | failed
    score: Mapped[int | None] = mapped_column(Integer, nullable=True)
    grade: Mapped[str | None] = mapped_column(String(1), nullable=True)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now_utc)

    modules: Mapped[list["ScanModule"]] = relationship(
        "ScanModule", back_populates="scan", cascade="all, delete-orphan"
    )


class ScanModule(Base):
    __tablename__ = "scan_modules"

    id: Mapped[str] = mapped_column(String, primary_key=True, default=new_uuid)
    scan_id: Mapped[str] = mapped_column(String, ForeignKey("scans.id", ondelete="CASCADE"), nullable=False)
    name: Mapped[str] = mapped_column(String, nullable=False)  # dns | tls | headers | reputation | subdomains | leaks
    status: Mapped[str] = mapped_column(String, default="pending")  # pending | running | completed | failed
    score: Mapped[int | None] = mapped_column(Integer, nullable=True)
    weight: Mapped[float] = mapped_column(Float, nullable=False)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    scan: Mapped["Scan"] = relationship("Scan", back_populates="modules")
    findings: Mapped[list["Finding"]] = relationship(
        "Finding", back_populates="module", cascade="all, delete-orphan"
    )


class Finding(Base):
    __tablename__ = "findings"

    id: Mapped[str] = mapped_column(String, primary_key=True, default=new_uuid)
    module_id: Mapped[str] = mapped_column(String, ForeignKey("scan_modules.id", ondelete="CASCADE"), nullable=False)
    severity: Mapped[str] = mapped_column(String, nullable=False)  # critical | high | medium | low | info
    title: Mapped[str] = mapped_column(String, nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    remediation: Mapped[str | None] = mapped_column(Text, nullable=True)
    raw_data: Mapped[str | None] = mapped_column(Text, nullable=True)  # JSON

    module: Mapped["ScanModule"] = relationship("ScanModule", back_populates="findings")
