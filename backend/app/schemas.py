from datetime import datetime
from pydantic import BaseModel, field_validator
import re


class ScanCreate(BaseModel):
    domain: str

    @field_validator("domain")
    @classmethod
    def validate_domain(cls, v: str) -> str:
        v = v.strip().lower().removeprefix("https://").removeprefix("http://")
        v = v.removesuffix("/")  # tolère un slash final mais rejette un vrai chemin
        # Convertit les domaines internationalisés (Unicode) en Punycode (xn--).
        # Indispensable pour que la victime puisse coller un domaine homographe
        # tel quel (« pаypal.com » avec un « а » cyrillique) : sans cette
        # conversion, la regex ASCII ci-dessous le rejetterait avant que le
        # scanner homographe ne puisse l'analyser. Les domaines ASCII purs sont
        # renvoyés inchangés par le codec idna.
        try:
            v = v.encode("idna").decode("ascii")
        except (UnicodeError, ValueError):
            raise ValueError("Domaine invalide")
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
