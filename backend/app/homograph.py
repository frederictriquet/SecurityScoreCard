"""Homograph domain analysis (IDN spoofing).

Primitives shared between two use cases:

- the DNS scanner (`scanners.dns._check_idn_homograph`) which CLASSIFIES into
  findings a domain that has already been validated and converted to Punycode;
- the validator (`schemas.validate_domain`) which, when it REJECTS a suspicious
  non-ASCII domain, must EXPLAIN why rather than return a terse "Invalid
  domain".

Centralizing the list of "confusable" characters and the heuristic script
detection here avoids any divergence between these two use cases (a list that
drifted from one file to the other would be a security blind spot).
"""

import unicodedata


# Unicode name prefixes that qualify a character without naming its writing
# system (e.g. "MODIFIER LETTER SMALL H", "FULLWIDTH LATIN …"). We skip them to
# reach the real script name and avoid fabricating fake "scripts" (MODIFIER,
# FULLWIDTH…) that would wrongly trigger a "mixed scripts" alert. Heuristic: see
# alpha_scripts.
_SCRIPT_NAME_QUALIFIERS = {
    "MODIFIER", "COMBINING", "FULLWIDTH", "HALFWIDTH", "MATHEMATICAL",
    "CIRCLED", "PARENTHESIZED", "SUPERSCRIPT", "SUBSCRIPT", "SMALL",
}


# Non-Latin characters whose appearance imitates a Latin ASCII letter.
# Used to detect homograph attacks (IDN spoofing).
# NOTE: deliberately partial allowlist (Cyrillic/Greek, the most common scripts
# for this kind of attack). Other homoglyph families (Armenian, fullwidth Latin,
# mathematical alphanumerics…) are not enumerated and therefore will NOT trigger
# the "confusable" branch (medium): they fall back to "info". The critical case
# of mixed scripts remains covered independently of this list (the "mixed
# scripts" branch, high).
CONFUSABLE_CHARS = {
    # Lowercase Cyrillic
    "а", "е", "о", "р", "с", "у", "х", "ѕ", "і", "ј", "һ", "ԁ", "ӏ", "ԛ", "ԝ",
    # Uppercase Cyrillic
    "А", "В", "Е", "К", "М", "Н", "О", "Р", "С", "Т", "У", "Х", "Ѕ", "І", "Ј",
    # Lowercase Greek
    "ο", "α", "ν", "ρ", "ι", "κ", "υ",
    # Uppercase Greek
    "Α", "Β", "Ε", "Ζ", "Η", "Ι", "Κ", "Μ", "Ν", "Ο", "Ρ", "Τ", "Υ", "Χ",
}


# Script combinations that may legitimately coexist within a single label
# (UTS#39, "Highly Restrictive" profile). Japanese normally mixes Han (CJK) +
# Hiragana + Katakana, plus the prolonged sound mark "ー" whose Unicode name
# starts with KATAKANA-HIRAGANA; Korean mixes Han + Hangul. These domains are
# perfectly valid and must NOT be flagged as homographs. NB: the scripts here
# are the Unicode name prefixes returned by `alpha_scripts` (heuristic), not the
# Unicode "Script" property.
_LEGIT_MULTISCRIPT_SETS = [
    {"CJK", "HIRAGANA", "KATAKANA", "KATAKANA-HIRAGANA"},  # Japanese
    {"CJK", "HANGUL"},                                      # Korean
]


def is_legit_multiscript(scripts: set[str]) -> bool:
    """True if the script mix corresponds to a legitimate combination.

    UTS#39 explicitly allows Han+Kana (Japanese) and Han+Hangul (Korean): a label
    whose set of scripts is a subset of one of these combinations is not a
    homograph attack but a normal IDN.
    """
    return any(scripts <= allowed for allowed in _LEGIT_MULTISCRIPT_SETS)


def script_of(ch: str) -> str | None:
    """Writing system (heuristic) of an alphabetic character, or None.

    Infers the script from the first "meaningful" word of the character's Unicode
    name ("LATIN SMALL LETTER A" → LATIN), skipping qualifying prefixes (MODIFIER,
    FULLWIDTH…). Returns None for non-alphabetic characters or characters without
    a Unicode name.
    """
    if not ch.isalpha():
        return None
    try:
        name = unicodedata.name(ch)
    except ValueError:
        return None
    words = name.split(" ")
    idx = 0
    while idx < len(words) - 1 and words[idx] in _SCRIPT_NAME_QUALIFIERS:
        idx += 1
    return words[idx]


def alpha_scripts(text: str) -> set[str]:
    """Returns the set of writing systems of the alphabetic characters.

    Heuristic (and not the Unicode "Script" property): see `script_of`. Enough to
    distinguish Latin/Cyrillic/Greek/CJK in a domain name, but not to be confused
    with real script detection.
    """
    scripts: set[str] = set()
    for ch in text:
        s = script_of(ch)
        if s is not None:
            scripts.add(s)
    return scripts


def build_homograph_explanation(raw: str) -> str | None:
    """Builds a detailed explanation if `raw` looks like a homograph.

    Used by the validator on the REJECT path: when a non-ASCII domain could not be
    validated, we want to tell the user *why* it is a problem rather than
    "Invalid domain".

    `raw` is the domain as submitted (visible Unicode form), before Punycode
    conversion. The analysis is done LABEL BY LABEL (separated by dots), like the
    DNS scanner: it is within a single label that a script mix betrays a
    homograph. Without this split, the ASCII TLD (".com") would always add LATIN
    and would make a legitimate IDN ("中国.com") look like a false positive.

    Returns:
    - an explanation string if at least one label exhibits a homograph signature
      — illegitimate script mix (e.g. "pаypal"), or label entirely composed of
      non-Latin confusable characters (e.g. "аррӏе");
    - None otherwise (pure ASCII, accented Latin, non-confusable IDN, legitimate
      script combination…), in which case the caller keeps its generic message.
      This avoids crying "homograph" over an honest IDN simply rejected for
      another reason (e.g. missing TLD).
    """
    suspicious = False
    for label in raw.split("."):
        letters = [c for c in label if c.isalpha()]
        if not letters:
            continue
        scripts = alpha_scripts(label)
        mixed = len(scripts) > 1 and not is_legit_multiscript(scripts)
        whole_confusable = (
            "LATIN" not in scripts and all(c in CONFUSABLE_CHARS for c in letters)
        )
        if mixed or whole_confusable:
            suspicious = True
            break

    if not suspicious:
        return None

    # List the suspicious characters (non-Latin or explicitly confusable),
    # deduplicated while preserving order of appearance.
    suspects: list[str] = []
    seen: set[str] = set()
    for c in raw:
        if not c.isalpha() or c in seen:
            continue
        if c in CONFUSABLE_CHARS or script_of(c) != "LATIN":
            seen.add(c)
            try:
                name = unicodedata.name(c)
            except ValueError:
                name = "unnamed character"
            suspects.append(f'"{c}" ({name}, U+{ord(c):04X})')

    # Real Punycode form (best-effort): reveals the gap with the imitated domain.
    try:
        puny = raw.encode("idna").decode("ascii")
    except (UnicodeError, ValueError):
        puny = None

    parts = [
        f'Homograph domain detected: "{raw}" contains one or more '
        "non-Latin characters that visually mimic ASCII letters.",
        f"Suspicious character(s): {', '.join(suspects)}.",
    ]
    if puny:
        parts.append(
            f'In its real form (Punycode), this domain is written "{puny}", '
            "which reveals that it differs from the Latin domain it imitates."
        )
    parts.append(
        "This is a homograph attack (IDN spoofing): an attacker registers a "
        "domain that looks almost identical to that of a legitimate site "
        "(bank, email provider, social network) to make you believe you are "
        "in the right place and to steal your credentials or payments."
    )
    parts.append(
        "Only proceed if you are certain of this domain's authenticity; "
        "when in doubt, enter it manually from a trusted source."
    )
    return " ".join(parts)
