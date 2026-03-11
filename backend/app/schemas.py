from datetime import datetime
from pydantic import BaseModel, field_validator
import re


class ScanCreate(BaseModel):
    domain: str

    @field_validator("domain")
    @classmethod
    def validate_domain(cls, v: str) -> str:
        v = v.strip().lower().removeprefix("https://").removeprefix("http://")
        v = v.split("/")[0].split("?")[0].split("#")[0]  # strip path, query, fragment
        pattern = r"^([a-z0-9]([a-z0-9\-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$"
        if not re.match(pattern, v):
            raise ValueError("Domaine invalide")
        return v


class FindingOut(BaseModel):
    id: str
    severity: str
    title: str
    description: str
    remediation: str | None

    model_config = {"from_attributes": True}


class ScanModuleOut(BaseModel):
    id: str
    name: str
    status: str
    score: int | None
    weight: float
    started_at: datetime | None
    completed_at: datetime | None
    findings: list[FindingOut] = []

    model_config = {"from_attributes": True}


class ScanOut(BaseModel):
    id: str
    domain: str
    status: str
    score: int | None
    grade: str | None
    started_at: datetime | None
    completed_at: datetime | None
    created_at: datetime
    modules: list[ScanModuleOut] = []

    model_config = {"from_attributes": True}


class ScanSummary(BaseModel):
    id: str
    domain: str
    status: str
    score: int | None
    grade: str | None
    created_at: datetime

    model_config = {"from_attributes": True}
