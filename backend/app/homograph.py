"""Analyse des domaines homographes (IDN spoofing).

Primitives partagées entre deux usages :

- le scanner DNS (`scanners.dns._check_idn_homograph`) qui CLASSE en findings un
  domaine déjà validé et converti en Punycode ;
- le validateur (`schemas.validate_domain`) qui, lorsqu'il REJETTE un domaine non
  ASCII suspect, doit EXPLIQUER pourquoi plutôt que renvoyer un laconique
  « Domaine invalide ».

Centraliser ici la liste des caractères « confusables » et la détection
heuristique de script évite toute divergence entre ces deux usages (une liste qui
dériverait d'un fichier à l'autre serait un angle mort de sécurité).
"""

import unicodedata


# Préfixes de noms Unicode qui qualifient un caractère sans désigner son
# système d'écriture (ex. « MODIFIER LETTER SMALL H », « FULLWIDTH LATIN … »).
# On les saute pour atteindre le vrai nom de script et éviter de fabriquer de
# faux « scripts » (MODIFIER, FULLWIDTH…) qui déclencheraient à tort une alerte
# « scripts mélangés ». Heuristique : voir alpha_scripts.
_SCRIPT_NAME_QUALIFIERS = {
    "MODIFIER", "COMBINING", "FULLWIDTH", "HALFWIDTH", "MATHEMATICAL",
    "CIRCLED", "PARENTHESIZED", "SUPERSCRIPT", "SUBSCRIPT", "SMALL",
}


# Caractères non latins dont l'apparence imite une lettre ASCII latine.
# Sert à détecter les attaques homographes (IDN spoofing).
# NOTE : liste blanche volontairement partielle (cyrillique/grec, les scripts
# les plus courants pour ce type d'attaque). D'autres familles d'homoglyphes
# (arménien, latin pleine-chasse, alphanumériques mathématiques…) ne sont pas
# énumérées et ne déclencheront donc PAS la branche « confusable » (medium) :
# elles retombent en « info ». Le cas critique du mélange de scripts reste
# couvert indépendamment de cette liste (branche « scripts mélangés », high).
CONFUSABLE_CHARS = {
    # Cyrillique minuscule
    "а", "е", "о", "р", "с", "у", "х", "ѕ", "і", "ј", "һ", "ԁ", "ӏ", "ԛ", "ԝ",
    # Cyrillique majuscule
    "А", "В", "Е", "К", "М", "Н", "О", "Р", "С", "Т", "У", "Х", "Ѕ", "І", "Ј",
    # Grec minuscule
    "ο", "α", "ν", "ρ", "ι", "κ", "υ",
    # Grec majuscule
    "Α", "Β", "Ε", "Ζ", "Η", "Ι", "Κ", "Μ", "Ν", "Ο", "Ρ", "Τ", "Υ", "Χ",
}


# Combinaisons de scripts pouvant légitimement coexister dans un même label
# (UTS#39, profil « Highly Restrictive »). Le japonais mélange normalement Han
# (CJK) + Hiragana + Katakana, plus la marque d'allongement « ー » dont le nom
# Unicode commence par KATAKANA-HIRAGANA ; le coréen mélange Han + Hangul. Ces
# domaines sont parfaitement valides et ne doivent PAS être signalés comme
# homographes. NB : les scripts sont ici les préfixes de noms Unicode renvoyés
# par `alpha_scripts` (heuristique), pas la propriété Unicode « Script ».
_LEGIT_MULTISCRIPT_SETS = [
    {"CJK", "HIRAGANA", "KATAKANA", "KATAKANA-HIRAGANA"},  # japonais
    {"CJK", "HANGUL"},                                      # coréen
]


def is_legit_multiscript(scripts: set[str]) -> bool:
    """Vrai si le mélange de scripts correspond à une combinaison légitime.

    UTS#39 autorise explicitement Han+Kana (japonais) et Han+Hangul (coréen) :
    un label dont l'ensemble des scripts est un sous-ensemble de l'une de ces
    combinaisons n'est pas une attaque homographe mais un IDN normal.
    """
    return any(scripts <= allowed for allowed in _LEGIT_MULTISCRIPT_SETS)


def script_of(ch: str) -> str | None:
    """Système d'écriture (heuristique) d'un caractère alphabétique, ou None.

    Déduit le script du premier mot « significatif » du nom Unicode du caractère
    (« LATIN SMALL LETTER A » → LATIN), en sautant les préfixes qualificatifs
    (MODIFIER, FULLWIDTH…). Retourne None pour les caractères non alphabétiques
    ou sans nom Unicode.
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
    """Retourne l'ensemble des systèmes d'écriture des caractères alphabétiques.

    Heuristique (et non la propriété Unicode « Script ») : voir `script_of`.
    Suffisant pour distinguer latin/cyrillique/grec/CJK dans un nom de domaine,
    mais à ne pas confondre avec une vraie détection de script.
    """
    scripts: set[str] = set()
    for ch in text:
        s = script_of(ch)
        if s is not None:
            scripts.add(s)
    return scripts


def build_homograph_explanation(raw: str) -> str | None:
    """Construit une explication détaillée si `raw` ressemble à un homographe.

    Utilisé par le validateur sur le chemin de REJET : quand un domaine non ASCII
    n'a pas pu être validé, on veut dire à l'utilisateur *pourquoi* c'est un
    problème plutôt que « Domaine invalide ».

    `raw` est le domaine tel que soumis (forme Unicode visible), avant conversion
    Punycode. L'analyse se fait LABEL PAR LABEL (séparés par des points), comme le
    scanner DNS : c'est au sein d'un même label qu'un mélange de scripts trahit un
    homographe. Sans ce découpage, le TLD ASCII (« .com ») ajouterait toujours du
    LATIN et ferait passer un IDN légitime (« 中国.com ») pour un faux positif.

    Retourne :
    - une chaîne d'explication si au moins un label présente une signature
      homographe — mélange de scripts non légitime (ex. « pаypal »), ou label
      entièrement composé de caractères confusables non latins (ex. « аррӏе ») ;
    - None sinon (ASCII pur, latin accentué, IDN non confusable, combinaison de
      scripts légitime…), auquel cas l'appelant conserve son message générique.
      On évite ainsi de crier « homographe » sur un IDN honnête simplement rejeté
      pour une autre raison (ex. TLD manquant).
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

    # Liste les caractères suspects (non latins ou explicitement confusables),
    # dédupliqués en conservant l'ordre d'apparition.
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
                name = "caractère non nommé"
            suspects.append(f"« {c} » ({name}, U+{ord(c):04X})")

    # Forme Punycode réelle (best-effort) : révèle l'écart avec le domaine imité.
    try:
        puny = raw.encode("idna").decode("ascii")
    except (UnicodeError, ValueError):
        puny = None

    parts = [
        f"Domaine homographe détecté : « {raw} » contient un ou plusieurs "
        "caractères non latins qui imitent visuellement des lettres ASCII.",
        f"Caractère(s) suspect(s) : {', '.join(suspects)}.",
    ]
    if puny:
        parts.append(
            f"Sous sa forme réelle (Punycode), ce domaine s'écrit « {puny} », "
            "ce qui révèle qu'il diffère du domaine latin qu'il imite."
        )
    parts.append(
        "Il s'agit d'une attaque homographe (IDN spoofing) : un attaquant "
        "enregistre un domaine d'apparence quasi identique à celui d'un site "
        "légitime (banque, messagerie, réseau social) afin de vous faire croire "
        "que vous êtes au bon endroit et de vous soutirer identifiants ou "
        "paiements."
    )
    parts.append(
        "Ne poursuivez que si vous êtes certain de l'authenticité de ce domaine ; "
        "dans le doute, saisissez-le manuellement depuis une source de confiance."
    )
    return " ".join(parts)
