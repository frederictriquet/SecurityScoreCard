"""Tests for app.homograph — shared homograph analysis primitives.

Covers `build_homograph_explanation` (used by the validator to explain the
rejection of a homograph domain) as well as the script detection helpers, which
are also consumed by the DNS scanner.
"""

from app.homograph import (
    alpha_scripts,
    build_homograph_explanation,
    is_legit_multiscript,
    script_of,
)


class TestScriptHelpers:
    def test_script_of_latin(self):
        assert script_of("a") == "LATIN"

    def test_script_of_cyrillic(self):
        assert script_of("а") == "CYRILLIC"  # U+0430 (Cyrillic)

    def test_script_of_non_alpha_is_none(self):
        assert script_of("1") is None
        assert script_of("-") is None

    def test_alpha_scripts_mixed(self):
        assert alpha_scripts("pаypal") == {"LATIN", "CYRILLIC"}

    def test_alpha_scripts_ignores_digits_and_hyphen(self):
        assert alpha_scripts("a1-b") == {"LATIN"}

    def test_is_legit_multiscript_japanese(self):
        assert is_legit_multiscript({"CJK", "HIRAGANA"}) is True

    def test_is_legit_multiscript_latin_cyrillic_false(self):
        assert is_legit_multiscript({"LATIN", "CYRILLIC"}) is False


class TestBuildHomographExplanation:
    def test_mixed_script_explained(self):
        msg = build_homograph_explanation("pаypal.com")  # Cyrillic "а"
        assert msg is not None
        assert "homograph" in msg.lower()
        assert "CYRILLIC SMALL LETTER A" in msg
        assert "U+0430" in msg

    def test_whole_confusable_explained(self):
        msg = build_homograph_explanation("gооgle")  # Cyrillic "о"
        assert msg is not None
        assert "homograph" in msg.lower()

    def test_explanation_includes_punycode(self):
        msg = build_homograph_explanation("pаypal.com")
        assert msg is not None
        assert "xn--" in msg

    def test_explanation_includes_why_dangerous(self):
        msg = build_homograph_explanation("pаypal.com")
        assert msg is not None
        assert "IDN spoofing" in msg
        assert "legitimate" in msg

    def test_pure_ascii_returns_none(self):
        assert build_homograph_explanation("paypal.com") is None

    def test_accented_latin_returns_none(self):
        # "café": single-script accented Latin, not a homograph.
        assert build_homograph_explanation("café.com") is None

    def test_legit_cjk_returns_none(self):
        # Legitimate CJK IDN, non-confusable, single-script → no alert.
        assert build_homograph_explanation("中国.com") is None

    def test_japanese_multiscript_returns_none(self):
        # Han + Hiragana is a legitimate combination (UTS#39) → no alert.
        assert build_homograph_explanation("東京めがね.jp") is None

    def test_empty_returns_none(self):
        assert build_homograph_explanation("") is None

    def test_only_suspect_chars_listed(self):
        # Only non-Latin/confusable characters are listed, not the Latin ones.
        msg = build_homograph_explanation("pаypal.com")
        assert msg is not None
        # "p", "y", "l" (Latin) must not appear as suspicious.
        assert "LATIN SMALL LETTER P" not in msg
        assert "CYRILLIC SMALL LETTER A" in msg
