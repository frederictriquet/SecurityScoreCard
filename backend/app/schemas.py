from dataclasses import dataclass
from datetime import datetime
from pydantic import BaseModel, model_validator
import re

from app.homograph import build_homograph_explanation


def _reject_domain(original: str) -> "ValueError":
    """Construit l'erreur de rejet d'un domaine.

    Si l'entrée présente une signature homographe (caractère non latin imitant
    une lettre ASCII, mélange de scripts), on renvoie une explication détaillée
    du danger plutôt qu'un laconique « Domaine invalide » : c'est précisément le
    cas d'un domaine spoofé que l'utilisateur pourrait coller sans comprendre
    pourquoi il est refusé. Sinon, message générique.
    """
    return ValueError(build_homograph_explanation(original) or "Domaine invalide")


# Le dernier label accepte aussi un TLD internationalisé (ccTLD/gTLD IDN) qui,
# après conversion idna, devient un label Punycode « xn--… » contenant chiffres
# et tirets (ex. « .рф » → « xn--p1ai »).
_DOMAIN_PATTERN = re.compile(
    r"^([a-z0-9]([a-z0-9\-]{0,61}[a-z0-9])?\.)+([a-z]{2,}|xn--[a-z0-9\-]+)$"
)


@dataclass
class DomainInspection:
    """Résultat de la normalisation/validation d'un domaine soumis.

    - `visible` : forme Unicode visible saisie (minuscule, schéma et slash
      retirés) — celle que l'utilisateur croit avoir tapée ;
    - `punycode` : forme ASCII/Punycode réellement scannée ;
    - `homograph_explanation` : explication détaillée du danger si la forme
      visible présente une signature homographe, sinon None.
    """

    visible: str
    punycode: str
    homograph_explanation: str | None


def inspect_domain(raw: str) -> DomainInspection:
    """Normalise, valide et inspecte un domaine soumis.

    Lève `ValueError` (→ 422) si le domaine est invalide, en expliquant le
    danger lorsqu'il s'agit d'un homographe non convertible. Pour un domaine
    valide mais homographe (ex. « pаypal.com » avec un « а » cyrillique), la
    validation réussit et `homograph_explanation` est renseignée : l'appelant
    pourra alors demander une confirmation explicite avant de scanner.
    """
    v = raw.strip().lower().removeprefix("https://").removeprefix("http://")
    v = v.removesuffix("/")  # tolère un slash final mais rejette un vrai chemin
    visible = v  # forme visible soumise, conservée pour expliquer le danger
    # Convertit les domaines internationalisés (Unicode) en Punycode (xn--).
    # Indispensable pour que la victime puisse coller un domaine homographe
    # tel quel (« pаypal.com » avec un « а » cyrillique) : sans cette
    # conversion, la regex ASCII ci-dessous le rejetterait avant que le
    # scanner homographe ne puisse l'analyser. Les domaines ASCII purs sont
    # renvoyés inchangés par le codec idna.
    # NB : ce codec implémente IDNA2003 (mapping silencieux non conforme aux
    # navigateurs modernes / UTS#46, ex. « straße.de » → « strasse.de ») ;
    # cf. la limite documentée dans DnsScanner._check_idn_homograph.
    try:
        puny = v.encode("idna").decode("ascii")
    except (UnicodeError, ValueError):
        raise _reject_domain(visible)
    if not _DOMAIN_PATTERN.match(puny):
        raise _reject_domain(visible)
    # Domaine valide : reste à savoir s'il présente une signature homographe
    # (cas d'un homographe convertible en Punycode, qui passe la validation mais
    # mérite une confirmation explicite avant de lancer le scan).
    return DomainInspection(
        visible=visible,
        punycode=puny,
        homograph_explanation=build_homograph_explanation(visible),
    )


class ScanCreate(BaseModel):
    domain: str
    # Confirmation explicite de l'utilisateur pour scanner un domaine homographe.
    # Sans elle, le routeur refuse de lancer le scan d'un domaine trompeur.
    confirm: bool = False
    # Champs dérivés, calculés à la validation (cf. inspect_domain) : la forme
    # visible saisie et l'explication du danger si signature homographe détectée.
    # Exposés pour que le routeur construise la réponse « confirmation requise ».
    visible_domain: str = ""
    homograph_explanation: str | None = None

    @model_validator(mode="before")
    @classmethod
    def _validate_domain(cls, data):
        # `data` est le dict de la requête ; on ne transforme que si « domain »
        # est bien une chaîne (sinon on laisse Pydantic signaler le champ manquant
        # ou de mauvais type).
        if isinstance(data, dict) and isinstance(data.get("domain"), str):
            insp = inspect_domain(data["domain"])
            data = {
                **data,
                "domain": insp.punycode,
                "visible_domain": insp.visible,
                "homograph_explanation": insp.homograph_explanation,
            }
        return data


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
