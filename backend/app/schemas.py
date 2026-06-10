from dataclasses import dataclass
from datetime import datetime
from pydantic import BaseModel, model_validator
import re
from urllib.parse import urlsplit

from app.homograph import build_homograph_explanation


def _reject_domain(original: str) -> "ValueError":
    """Builds the rejection error for a domain.

    If the input exhibits a homograph signature (non-Latin character imitating an
    ASCII letter, script mix), we return a detailed explanation of the danger
    rather than a terse "Invalid domain": this is precisely the case of a
    spoofed domain that the user might paste without understanding why it is
    refused. Otherwise, a generic message.
    """
    return ValueError(build_homograph_explanation(original) or "Invalid domain")


# The last label also accepts an internationalized TLD (ccTLD/gTLD IDN) which,
# after idna conversion, becomes a Punycode label "xn--…" containing digits and
# hyphens (e.g. ".рф" → "xn--p1ai").
_DOMAIN_PATTERN = re.compile(
    r"^([a-z0-9]([a-z0-9\-]{0,61}[a-z0-9])?\.)+([a-z]{2,}|xn--[a-z0-9\-]+)$"
)


@dataclass
class DomainInspection:
    """Result of the normalization/validation of a submitted domain.

    - `visible`: visible Unicode form of the bare host (lowercased, with any
      scheme, userinfo, port, path, query and fragment stripped) — the host the
      user effectively targets and the one the homograph explanation refers to;
    - `punycode`: ASCII/Punycode form actually scanned;
    - `homograph_explanation`: detailed explanation of the danger if the visible
      form exhibits a homograph signature, otherwise None.
    """

    visible: str
    punycode: str
    homograph_explanation: str | None


def _extract_host(raw: str) -> str | None:
    """Reduces a pasted URL to its bare registrable host.

    Strips the scheme, userinfo (``user:pass@``), port (``:8080``), path, query
    (``?…``) and fragment (``#…``) plus surrounding whitespace, so that a full
    URL pasted from a browser bar (e.g.
    ``https://user:pass@example.com:8080/login?next=/#top``) is reduced to its
    host (``example.com``) before validation — matching the UI promise to accept
    pasted URLs.

    Uses ``urllib.parse`` rather than ad-hoc string ops. A bare domain without a
    scheme (e.g. ``example.com``) is placed by ``urlsplit`` in ``path`` rather
    than ``netloc``; prefixing ``//`` forces it to be parsed as an authority so
    the host is extracted uniformly. ``hostname`` already lowercases the host and
    drops userinfo/port. Returns ``None`` when no host can be extracted (empty
    input, malformed authority…), leaving the caller to reject it.
    """
    candidate = raw.strip()
    if not candidate:
        return None
    # No authority delimiter and no scheme: treat the whole input as a host.
    if "://" not in candidate and not candidate.startswith("//"):
        candidate = "//" + candidate
    try:
        return urlsplit(candidate).hostname
    except ValueError:
        return None


def inspect_domain(raw: str) -> DomainInspection:
    """Normalizes, validates and inspects a submitted domain.

    Raises `ValueError` (→ 422) if the domain is invalid, explaining the danger
    when it is a non-convertible homograph. For a valid but homograph domain
    (e.g. "pаypal.com" with a Cyrillic "а"), validation succeeds and
    `homograph_explanation` is populated: the caller can then request explicit
    confirmation before scanning.
    """
    host = _extract_host(raw)
    if not host:
        raise _reject_domain(raw.strip())
    v = host  # bare host, scheme/userinfo/port/path/query/fragment already gone
    visible = v  # visible form of the host, kept to explain the danger
    # Convert internationalized domains (Unicode) to Punycode (xn--).
    # Essential so that the victim can paste a homograph domain as-is
    # ("pаypal.com" with a Cyrillic "а"): without this conversion, the ASCII
    # regex below would reject it before the homograph scanner could analyze
    # it. Pure ASCII domains are returned unchanged by the idna codec.
    # NB: this codec implements IDNA2003 (silent mapping not conformant to
    # modern browsers / UTS#46, e.g. "straße.de" → "strasse.de");
    # cf. the limitation documented in DnsScanner._check_idn_homograph.
    try:
        puny = v.encode("idna").decode("ascii")
    except (UnicodeError, ValueError):
        raise _reject_domain(visible)
    if not _DOMAIN_PATTERN.match(puny):
        raise _reject_domain(visible)
    # Valid domain: it remains to determine whether it exhibits a homograph
    # signature (the case of a Punycode-convertible homograph, which passes
    # validation but deserves explicit confirmation before launching the scan).
    return DomainInspection(
        visible=visible,
        punycode=puny,
        homograph_explanation=build_homograph_explanation(visible),
    )


class ScanCreate(BaseModel):
    domain: str
    # Explicit user confirmation to scan a homograph domain. Without it, the
    # router refuses to launch the scan of a deceptive domain.
    confirm: bool = False
    # Derived fields, computed at validation (cf. inspect_domain): the visible
    # form entered and the explanation of the danger if a homograph signature is
    # detected. Exposed so the router can build the "confirmation required"
    # response.
    visible_domain: str = ""
    homograph_explanation: str | None = None

    @model_validator(mode="before")
    @classmethod
    def _validate_domain(cls, data):
        # `data` is the request dict; we only transform if "domain" is indeed a
        # string (otherwise we let Pydantic report the missing or wrongly typed
        # field).
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


class FindingRef(BaseModel):
    """Stable reference to a finding, used to diff two scans.

    A finding's identity is its (module, title) pair, not the DB id, so the same
    issue detected across two scans of a domain compares equal.
    """

    module: str
    severity: str
    title: str


class ScanComparison(BaseModel):
    """Diff of a scan against the previous scan of the same domain.

    When there is no previous scan, ``previous_scan`` is ``None``, ``score_delta``
    and ``grade_change`` are absent, and both finding lists are empty.
    """

    scan_id: str
    previous_scan: ScanSummary | None = None
    score_delta: int | None = None
    grade_change: str | None = None  # e.g. "C->B" when the grade changed
    new_findings: list[FindingRef] = []
    resolved_findings: list[FindingRef] = []
