"""Tests pour app.scanners.headers — Headers, cookies, SRI, mixed content, CORS, fichiers exposés."""

import pytest
from unittest.mock import patch, AsyncMock, MagicMock

import httpx

from app.scanners.headers import (
    HeadersScanner,
    _HTMLSecurityParser,
    _analyze_cookie,
    _check_cors,
    _check_exposed_files,
    _check_cookies,
    SECURITY_HEADERS,
    COOKIE_PROBE_PATHS,
)


@pytest.fixture
def scanner():
    return HeadersScanner()


# ===================================================================
# _HTMLSecurityParser — SRI
# ===================================================================


class TestHTMLParserSRI:
    def test_cross_origin_script_without_integrity(self):
        parser = _HTMLSecurityParser("example.com")
        parser.feed('<script src="https://cdn.example.org/lib.js"></script>')
        assert len(parser.sri_issues) == 1
        assert parser.sri_issues[0][0] == "script"
        assert "cdn.example.org" in parser.sri_issues[0][2]

    def test_cross_origin_script_with_integrity(self):
        parser = _HTMLSecurityParser("example.com")
        parser.feed(
            '<script src="https://cdn.example.org/lib.js" '
            'integrity="sha384-abc123"></script>'
        )
        assert len(parser.sri_issues) == 0

    def test_same_origin_script_no_sri_issue(self):
        parser = _HTMLSecurityParser("example.com")
        parser.feed('<script src="https://example.com/app.js"></script>')
        assert len(parser.sri_issues) == 0

    def test_relative_script_no_sri_issue(self):
        parser = _HTMLSecurityParser("example.com")
        parser.feed('<script src="/js/app.js"></script>')
        assert len(parser.sri_issues) == 0

    def test_cross_origin_stylesheet_without_integrity(self):
        parser = _HTMLSecurityParser("example.com")
        parser.feed(
            '<link rel="stylesheet" href="https://cdn.example.org/style.css">'
        )
        assert len(parser.sri_issues) == 1
        assert parser.sri_issues[0][0] == "link"

    def test_cross_origin_stylesheet_with_integrity(self):
        parser = _HTMLSecurityParser("example.com")
        parser.feed(
            '<link rel="stylesheet" href="https://cdn.example.org/style.css" '
            'integrity="sha384-xyz">'
        )
        assert len(parser.sri_issues) == 0

    def test_link_not_stylesheet_ignored(self):
        parser = _HTMLSecurityParser("example.com")
        parser.feed('<link rel="icon" href="https://cdn.example.org/favicon.ico">')
        assert len(parser.sri_issues) == 0

    def test_dedup_same_host_same_tag(self):
        parser = _HTMLSecurityParser("example.com")
        parser.feed(
            '<script src="https://cdn.example.org/a.js"></script>'
            '<script src="https://cdn.example.org/b.js"></script>'
        )
        assert len(parser.sri_issues) == 1  # même (tag, host) dédupliqué

    def test_different_hosts_not_deduped(self):
        parser = _HTMLSecurityParser("example.com")
        parser.feed(
            '<script src="https://cdn1.example.org/a.js"></script>'
            '<script src="https://cdn2.example.org/b.js"></script>'
        )
        assert len(parser.sri_issues) == 2


# ===================================================================
# _HTMLSecurityParser — Mixed Content
# ===================================================================


class TestHTMLParserMixedContent:
    def test_http_script_detected(self):
        parser = _HTMLSecurityParser("example.com")
        parser.feed('<script src="http://cdn.example.org/lib.js"></script>')
        assert len(parser.mixed_content) == 1
        assert parser.mixed_content[0][0] == "script"

    def test_https_script_no_issue(self):
        parser = _HTMLSecurityParser("example.com")
        parser.feed('<script src="https://cdn.example.org/lib.js"></script>')
        assert len(parser.mixed_content) == 0

    def test_http_img_detected(self):
        parser = _HTMLSecurityParser("example.com")
        parser.feed('<img src="http://cdn.example.org/image.png">')
        assert len(parser.mixed_content) == 1
        assert parser.mixed_content[0][0] == "img"

    def test_http_iframe_detected(self):
        parser = _HTMLSecurityParser("example.com")
        parser.feed('<iframe src="http://evil.com/page"></iframe>')
        assert len(parser.mixed_content) == 1
        assert parser.mixed_content[0][0] == "iframe"

    def test_http_video_detected(self):
        parser = _HTMLSecurityParser("example.com")
        parser.feed('<video src="http://cdn.example.org/video.mp4"></video>')
        assert len(parser.mixed_content) == 1

    def test_http_audio_detected(self):
        parser = _HTMLSecurityParser("example.com")
        parser.feed('<audio src="http://cdn.example.org/audio.mp3"></audio>')
        assert len(parser.mixed_content) == 1

    def test_http_source_detected(self):
        parser = _HTMLSecurityParser("example.com")
        parser.feed('<source src="http://cdn.example.org/vid.webm">')
        assert len(parser.mixed_content) == 1

    def test_http_embed_detected(self):
        parser = _HTMLSecurityParser("example.com")
        parser.feed('<embed src="http://cdn.example.org/file.swf">')
        assert len(parser.mixed_content) == 1

    def test_http_object_detected(self):
        parser = _HTMLSecurityParser("example.com")
        parser.feed('<object src="http://cdn.example.org/obj"></object>')
        assert len(parser.mixed_content) == 1

    def test_relative_src_no_mixed_content(self):
        parser = _HTMLSecurityParser("example.com")
        parser.feed('<img src="/images/logo.png">')
        assert len(parser.mixed_content) == 0

    def test_dedup_mixed_content_same_tag_host(self):
        parser = _HTMLSecurityParser("example.com")
        parser.feed(
            '<img src="http://cdn.example.org/a.png">'
            '<img src="http://cdn.example.org/b.png">'
        )
        assert len(parser.mixed_content) == 1

    def test_http_stylesheet_mixed_content(self):
        parser = _HTMLSecurityParser("example.com")
        parser.feed(
            '<link rel="stylesheet" href="http://cdn.example.org/style.css">'
        )
        assert len(parser.mixed_content) == 1

    def test_combined_sri_and_mixed_content(self):
        parser = _HTMLSecurityParser("example.com")
        parser.feed('<script src="http://cdn.example.org/lib.js"></script>')
        assert len(parser.sri_issues) == 1  # cross-origin sans integrity
        assert len(parser.mixed_content) == 1  # HTTP


# ===================================================================
# _analyze_cookie
# ===================================================================


class TestAnalyzeCookie:
    def test_secure_cookie_no_finding(self):
        findings = []
        seen = set()
        _analyze_cookie("session=abc; Secure; HttpOnly; SameSite=Lax", "/", seen, findings)
        assert len(findings) == 0

    def test_missing_secure(self):
        findings = []
        seen = set()
        _analyze_cookie("session=abc; HttpOnly; SameSite=Lax", "/", seen, findings)
        secure_findings = [f for f in findings if "Secure" in f.title]
        assert len(secure_findings) == 1
        assert secure_findings[0].severity == "medium"

    def test_missing_httponly(self):
        findings = []
        seen = set()
        _analyze_cookie("session=abc; Secure; SameSite=Lax", "/", seen, findings)
        httponly_findings = [f for f in findings if "HttpOnly" in f.title]
        assert len(httponly_findings) == 1
        assert httponly_findings[0].severity == "medium"

    def test_missing_samesite(self):
        findings = []
        seen = set()
        _analyze_cookie("session=abc; Secure; HttpOnly", "/", seen, findings)
        samesite_findings = [f for f in findings if "SameSite" in f.title]
        assert len(samesite_findings) == 1
        assert samesite_findings[0].severity == "low"

    def test_samesite_none_without_secure(self):
        findings = []
        seen = set()
        _analyze_cookie("session=abc; HttpOnly; SameSite=None", "/", seen, findings)
        # Missing Secure → medium finding
        # SameSite=None without Secure → high finding
        samesite_findings = [f for f in findings if "SameSite=None" in f.title]
        assert len(samesite_findings) == 1
        assert samesite_findings[0].severity == "high"

    def test_samesite_none_with_secure_ok(self):
        findings = []
        seen = set()
        _analyze_cookie("session=abc; Secure; HttpOnly; SameSite=None", "/", seen, findings)
        samesite_findings = [f for f in findings if "SameSite" in f.title]
        assert len(samesite_findings) == 0

    def test_all_attributes_missing(self):
        findings = []
        seen = set()
        _analyze_cookie("session=abc", "/", seen, findings)
        assert len(findings) == 3  # Secure, HttpOnly, SameSite

    def test_dedup_same_cookie_name(self):
        findings = []
        seen = set()
        _analyze_cookie("session=abc", "/", seen, findings)
        assert len(findings) == 3
        findings2 = []
        _analyze_cookie("session=abc", "/login", seen, findings2)
        assert len(findings2) == 0  # déjà vu

    def test_different_cookie_names_not_deduped(self):
        findings = []
        seen = set()
        _analyze_cookie("session=abc", "/", seen, findings)
        _analyze_cookie("token=xyz", "/", seen, findings)
        assert len(findings) == 6  # 3 issues par cookie

    def test_cookie_name_extracted_correctly(self):
        findings = []
        seen = set()
        _analyze_cookie("my_cookie=value123; HttpOnly", "/", seen, findings)
        secure_finding = [f for f in findings if "Secure" in f.title]
        assert "my_cookie" in secure_finding[0].title

    def test_path_shown_in_finding(self):
        findings = []
        seen = set()
        _analyze_cookie("sess=v", "/login", seen, findings)
        assert any("/login" in f.title for f in findings)


# ===================================================================
# _check_cors
# ===================================================================


class TestCheckCors:
    async def test_cors_wildcard(self):
        import respx

        findings = []
        with respx.mock:
            respx.get("https://example.com").mock(
                return_value=httpx.Response(
                    200,
                    headers={"access-control-allow-origin": "*"},
                )
            )
            await _check_cors("https://example.com", findings)
        assert len(findings) == 1
        assert findings[0].severity == "medium"
        assert "*" in findings[0].title

    async def test_cors_reflection_with_credentials(self):
        import respx

        findings = []
        with respx.mock:
            respx.get("https://example.com").mock(
                return_value=httpx.Response(
                    200,
                    headers={
                        "access-control-allow-origin": "https://evil.example.com",
                        "access-control-allow-credentials": "true",
                    },
                )
            )
            await _check_cors("https://example.com", findings)
        assert len(findings) == 1
        assert findings[0].severity == "high"
        assert "credentials" in findings[0].title.lower()

    async def test_cors_reflection_without_credentials(self):
        import respx

        findings = []
        with respx.mock:
            respx.get("https://example.com").mock(
                return_value=httpx.Response(
                    200,
                    headers={
                        "access-control-allow-origin": "https://evil.example.com",
                    },
                )
            )
            await _check_cors("https://example.com", findings)
        assert len(findings) == 1
        assert findings[0].severity == "medium"
        assert "réflexion" in findings[0].title.lower()

    async def test_cors_no_header(self):
        import respx

        findings = []
        with respx.mock:
            respx.get("https://example.com").mock(
                return_value=httpx.Response(200)
            )
            await _check_cors("https://example.com", findings)
        assert len(findings) == 0

    async def test_cors_specific_origin_not_reflected(self):
        import respx

        findings = []
        with respx.mock:
            respx.get("https://example.com").mock(
                return_value=httpx.Response(
                    200,
                    headers={
                        "access-control-allow-origin": "https://trusted.example.com",
                    },
                )
            )
            await _check_cors("https://example.com", findings)
        assert len(findings) == 0

    async def test_cors_exception_silent(self):
        import respx

        findings = []
        with respx.mock:
            respx.get("https://example.com").mock(side_effect=httpx.ConnectError("fail"))
            await _check_cors("https://example.com", findings)
        assert len(findings) == 0


# ===================================================================
# _check_exposed_files
# ===================================================================


class TestCheckExposedFiles:
    async def test_git_head_exposed(self):
        import respx

        findings = []
        with respx.mock:
            # baseline 404
            respx.get("https://example.com/a-path-that-should-not-exist-82719").mock(
                return_value=httpx.Response(404)
            )
            respx.get("https://example.com/.git/HEAD").mock(
                return_value=httpx.Response(200, text="ref: refs/heads/main\n")
            )
            respx.get("https://example.com/.env").mock(
                return_value=httpx.Response(404)
            )
            respx.get("https://example.com/.svn/entries").mock(
                return_value=httpx.Response(404)
            )
            respx.get("https://example.com/web.config").mock(
                return_value=httpx.Response(404)
            )
            respx.get("https://example.com/.well-known/security.txt").mock(
                return_value=httpx.Response(404)
            )
            await _check_exposed_files("https://example.com", findings)

        git_findings = [f for f in findings if ".git" in f.title.lower() or "Git" in f.title]
        assert len(git_findings) == 1
        assert git_findings[0].severity == "critical"

    async def test_env_exposed(self):
        import respx

        findings = []
        with respx.mock:
            respx.get("https://example.com/a-path-that-should-not-exist-82719").mock(
                return_value=httpx.Response(404)
            )
            respx.get("https://example.com/.git/HEAD").mock(
                return_value=httpx.Response(404)
            )
            respx.get("https://example.com/.env").mock(
                return_value=httpx.Response(
                    200,
                    text="DB_PASSWORD=secret\nAPI_KEY=abc123",
                    headers={"content-type": "text/plain"},
                )
            )
            respx.get("https://example.com/.svn/entries").mock(
                return_value=httpx.Response(404)
            )
            respx.get("https://example.com/web.config").mock(
                return_value=httpx.Response(404)
            )
            respx.get("https://example.com/.well-known/security.txt").mock(
                return_value=httpx.Response(404)
            )
            await _check_exposed_files("https://example.com", findings)

        env_findings = [f for f in findings if ".env" in f.title]
        assert len(env_findings) == 1
        assert env_findings[0].severity == "critical"

    async def test_env_html_response_filtered(self):
        """Un .env qui renvoie du HTML est probablement une page d'erreur custom."""
        import respx

        findings = []
        with respx.mock:
            respx.get("https://example.com/a-path-that-should-not-exist-82719").mock(
                return_value=httpx.Response(404)
            )
            respx.get("https://example.com/.git/HEAD").mock(
                return_value=httpx.Response(404)
            )
            respx.get("https://example.com/.env").mock(
                return_value=httpx.Response(
                    200,
                    text="<html>Not Found</html>",
                    headers={"content-type": "text/html"},
                )
            )
            respx.get("https://example.com/.svn/entries").mock(
                return_value=httpx.Response(404)
            )
            respx.get("https://example.com/web.config").mock(
                return_value=httpx.Response(404)
            )
            respx.get("https://example.com/.well-known/security.txt").mock(
                return_value=httpx.Response(404)
            )
            await _check_exposed_files("https://example.com", findings)

        env_findings = [f for f in findings if ".env" in f.title]
        assert len(env_findings) == 0

    async def test_web_config_exposed(self):
        import respx

        findings = []
        with respx.mock:
            respx.get("https://example.com/a-path-that-should-not-exist-82719").mock(
                return_value=httpx.Response(404)
            )
            respx.get("https://example.com/.git/HEAD").mock(
                return_value=httpx.Response(404)
            )
            respx.get("https://example.com/.env").mock(
                return_value=httpx.Response(404)
            )
            respx.get("https://example.com/.svn/entries").mock(
                return_value=httpx.Response(404)
            )
            respx.get("https://example.com/web.config").mock(
                return_value=httpx.Response(
                    200,
                    text='<?xml version="1.0"?><configuration><system.web></system.web></configuration>',
                )
            )
            respx.get("https://example.com/.well-known/security.txt").mock(
                return_value=httpx.Response(404)
            )
            await _check_exposed_files("https://example.com", findings)

        wc_findings = [f for f in findings if "web.config" in f.title]
        assert len(wc_findings) == 1
        assert wc_findings[0].severity == "high"

    async def test_web_config_without_signature_filtered(self):
        """web.config sans la signature <configuration → pas de finding."""
        import respx

        findings = []
        with respx.mock:
            respx.get("https://example.com/a-path-that-should-not-exist-82719").mock(
                return_value=httpx.Response(404)
            )
            respx.get("https://example.com/.git/HEAD").mock(
                return_value=httpx.Response(404)
            )
            respx.get("https://example.com/.env").mock(
                return_value=httpx.Response(404)
            )
            respx.get("https://example.com/.svn/entries").mock(
                return_value=httpx.Response(404)
            )
            respx.get("https://example.com/web.config").mock(
                return_value=httpx.Response(200, text="just some text")
            )
            respx.get("https://example.com/.well-known/security.txt").mock(
                return_value=httpx.Response(404)
            )
            await _check_exposed_files("https://example.com", findings)

        wc_findings = [f for f in findings if "web.config" in f.title]
        assert len(wc_findings) == 0

    async def test_security_txt_present(self):
        import respx

        findings = []
        with respx.mock:
            respx.get("https://example.com/a-path-that-should-not-exist-82719").mock(
                return_value=httpx.Response(404)
            )
            respx.get("https://example.com/.git/HEAD").mock(
                return_value=httpx.Response(404)
            )
            respx.get("https://example.com/.env").mock(
                return_value=httpx.Response(404)
            )
            respx.get("https://example.com/.svn/entries").mock(
                return_value=httpx.Response(404)
            )
            respx.get("https://example.com/web.config").mock(
                return_value=httpx.Response(404)
            )
            respx.get("https://example.com/.well-known/security.txt").mock(
                return_value=httpx.Response(
                    200,
                    text="Contact: security@example.com\nExpires: 2025-12-31T23:59:59.000Z",
                )
            )
            await _check_exposed_files("https://example.com", findings)

        sec_findings = [f for f in findings if "security.txt" in f.title]
        assert len(sec_findings) == 0  # Pas de finding car présent

    async def test_security_txt_absent(self):
        import respx

        findings = []
        with respx.mock:
            respx.get("https://example.com/a-path-that-should-not-exist-82719").mock(
                return_value=httpx.Response(404)
            )
            respx.get("https://example.com/.git/HEAD").mock(
                return_value=httpx.Response(404)
            )
            respx.get("https://example.com/.env").mock(
                return_value=httpx.Response(404)
            )
            respx.get("https://example.com/.svn/entries").mock(
                return_value=httpx.Response(404)
            )
            respx.get("https://example.com/web.config").mock(
                return_value=httpx.Response(404)
            )
            respx.get("https://example.com/.well-known/security.txt").mock(
                return_value=httpx.Response(404)
            )
            await _check_exposed_files("https://example.com", findings)

        sec_findings = [f for f in findings if "security.txt" in f.title]
        assert len(sec_findings) == 1
        assert sec_findings[0].severity == "info"

    async def test_custom_404_baseline_filtering(self):
        """Un serveur qui renvoie 200 pour tout avec le même contenu → filtré via baseline."""
        import respx

        generic_html = "<html><body>Page not found</body></html>"
        findings = []
        with respx.mock:
            respx.get("https://example.com/a-path-that-should-not-exist-82719").mock(
                return_value=httpx.Response(200, text=generic_html)
            )
            # .git/HEAD renvoie le même contenu (custom 404)
            respx.get("https://example.com/.git/HEAD").mock(
                return_value=httpx.Response(200, text=generic_html)
            )
            respx.get("https://example.com/.env").mock(
                return_value=httpx.Response(200, text=generic_html,
                                            headers={"content-type": "text/html"})
            )
            respx.get("https://example.com/.svn/entries").mock(
                return_value=httpx.Response(200, text=generic_html,
                                            headers={"content-type": "text/html"})
            )
            respx.get("https://example.com/web.config").mock(
                return_value=httpx.Response(200, text=generic_html)
            )
            respx.get("https://example.com/.well-known/security.txt").mock(
                return_value=httpx.Response(404)
            )
            await _check_exposed_files("https://example.com", findings)

        # Seul security.txt absent devrait apparaître
        file_findings = [f for f in findings if "security.txt" not in f.title]
        assert len(file_findings) == 0


# ===================================================================
# Full HeadersScanner scan — integration mock
# ===================================================================


class TestHeadersFullScan:
    async def test_all_headers_present_clean_scan(self, scanner):
        import respx

        headers = {
            "strict-transport-security": "max-age=31536000; includeSubDomains",
            "content-security-policy": "default-src 'self'",
            "x-frame-options": "DENY",
            "x-content-type-options": "nosniff",
            "referrer-policy": "strict-origin-when-cross-origin",
            "permissions-policy": "camera=(), microphone=()",
            "cross-origin-opener-policy": "same-origin",
            "cross-origin-embedder-policy": "require-corp",
            "cross-origin-resource-policy": "same-origin",
        }

        with respx.mock:
            # Main page
            respx.get("https://example.com").mock(
                return_value=httpx.Response(200, headers=headers, text="<html></html>")
            )
            # CORS check
            respx.get("https://example.com").mock(
                return_value=httpx.Response(200, headers=headers, text="<html></html>")
            )
            # Exposed files
            respx.get(url__regex=r"https://example\.com/.*").mock(
                return_value=httpx.Response(404)
            )
            # Cookie probes (HTTP)
            respx.get(url__regex=r"http://example\.com/.*").mock(
                return_value=httpx.Response(200)
            )

            result = await scanner.scan("example.com")
            # Seul security.txt absent devrait rester
            non_info_findings = [f for f in result.findings if f.severity != "info"]
            assert len(non_info_findings) == 0

    async def test_connection_failure(self, scanner):
        import respx

        with respx.mock:
            respx.get("https://example.com").mock(
                side_effect=httpx.ConnectError("fail")
            )
            result = await scanner.scan("example.com")
            assert result.findings[0].severity == "high"
            assert "Impossible" in result.findings[0].title

    async def test_missing_headers_detected(self, scanner):
        import respx

        with respx.mock:
            # Aucun header de sécurité
            respx.get(url__regex=r"https://example\.com.*").mock(
                return_value=httpx.Response(200, text="<html></html>")
            )
            respx.get(url__regex=r"http://example\.com.*").mock(
                return_value=httpx.Response(200)
            )

            result = await scanner.scan("example.com")
            titles = [f.title for f in result.findings]

            # Vérifie que tous les headers manquants sont détectés
            for h in SECURITY_HEADERS:
                assert h["title"] in titles, f"Missing finding for {h['name']}"

    async def test_leaky_headers_detected(self, scanner):
        import respx

        headers = {
            "server": "Apache/2.4.41",
            "x-powered-by": "Express",
        }
        # Ajouter tous les headers de sécurité pour ne pas polluer
        for h in SECURITY_HEADERS:
            headers[h["name"]] = "test-value"

        with respx.mock:
            respx.get(url__regex=r"https://example\.com.*").mock(
                return_value=httpx.Response(200, headers=headers, text="<html></html>")
            )
            respx.get(url__regex=r"http://example\.com.*").mock(
                return_value=httpx.Response(200)
            )

            result = await scanner.scan("example.com")
            leaky = [f for f in result.findings if "informatif" in f.title.lower()]
            assert len(leaky) >= 2
            assert any("server" in f.title.lower() for f in leaky)
            assert any("x-powered-by" in f.title.lower() for f in leaky)




# ===================================================================
# _check_cookies — orchestration multi-path réelle
# ===================================================================


class TestCheckCookies:
    async def test_probes_all_cookie_paths(self):
        """Vérifie que _check_cookies interroge tous les COOKIE_PROBE_PATHS."""
        import respx

        findings = []
        seen = set()
        probed_paths = []

        with respx.mock:
            for path in COOKIE_PROBE_PATHS:
                respx.get(f"https://example.com{path}").mock(
                    return_value=httpx.Response(200)
                )

            await _check_cookies("https://example.com", findings, seen)

        # Pas de cookies posés → pas de findings
        assert len(findings) == 0

    async def test_cookies_from_multiple_paths_deduped(self):
        """Le même cookie posé sur / et /login ne génère qu'un seul finding."""
        import respx

        findings = []
        seen = set()

        with respx.mock:
            for path in COOKIE_PROBE_PATHS:
                respx.get(f"https://example.com{path}").mock(
                    return_value=httpx.Response(
                        200,
                        headers={"set-cookie": "session=abc"},
                    )
                )

            await _check_cookies("https://example.com", findings, seen)

        # 3 issues (Secure, HttpOnly, SameSite) mais dédupliquées sur le nom
        assert len(findings) == 3
        assert all("session" in f.title for f in findings)

    async def test_different_cookies_from_different_paths(self):
        """Des cookies différents sur des paths différents sont tous détectés."""
        import respx

        findings = []
        seen = set()

        with respx.mock:
            respx.get("https://example.com/").mock(
                return_value=httpx.Response(
                    200,
                    headers={"set-cookie": "csrftoken=abc"},
                )
            )
            respx.get("https://example.com/login").mock(
                return_value=httpx.Response(
                    200,
                    headers={"set-cookie": "session=xyz"},
                )
            )
            # Les autres paths ne posent pas de cookies
            for path in COOKIE_PROBE_PATHS:
                if path not in ("/", "/login"):
                    respx.get(f"https://example.com{path}").mock(
                        return_value=httpx.Response(200)
                    )

            await _check_cookies("https://example.com", findings, seen)

        # 2 cookies × 3 issues = 6
        assert len(findings) == 6
        cookie_names = {f.title.split("'")[1] for f in findings}
        assert cookie_names == {"csrftoken", "session"}

    async def test_cookie_probe_path_exception_continues(self):
        """Une exception sur un path ne bloque pas les autres (L.343-344)."""
        import respx

        findings = []
        seen = set()

        with respx.mock:
            # Le premier path échoue
            respx.get("https://example.com/").mock(
                side_effect=httpx.ConnectError("timeout")
            )
            # /login pose un cookie
            respx.get("https://example.com/login").mock(
                return_value=httpx.Response(
                    200,
                    headers={"set-cookie": "sess=abc"},
                )
            )
            # Les autres paths OK sans cookies
            for path in COOKIE_PROBE_PATHS:
                if path not in ("/", "/login"):
                    respx.get(f"https://example.com{path}").mock(
                        return_value=httpx.Response(200)
                    )

            await _check_cookies("https://example.com", findings, seen)

        # Le cookie de /login est quand même détecté malgré l'erreur sur /
        assert len(findings) > 0
        assert any("sess" in f.title for f in findings)

    async def test_cookies_in_redirect_history(self):
        """Les cookies posés dans les réponses de redirection (resp.history) sont analysés (L.348)."""
        import respx

        findings = []
        seen = set()

        redirect_resp = httpx.Response(
            302,
            headers={
                "set-cookie": "redirect_cookie=val",
                "location": "https://example.com/dashboard",
            },
        )
        final_resp = httpx.Response(200)

        with respx.mock:
            # Simuler une redirection qui pose un cookie
            respx.get("https://example.com/login").mock(
                return_value=httpx.Response(
                    200,
                    headers={"set-cookie": "after_login=xyz"},
                )
            )
            # Les autres paths sans cookies
            for path in COOKIE_PROBE_PATHS:
                if path != "/login":
                    respx.get(f"https://example.com{path}").mock(
                        return_value=httpx.Response(200)
                    )

            await _check_cookies("https://example.com", findings, seen)

        assert any("after_login" in f.title for f in findings)

    async def test_http_vs_https_cookie_probing(self):
        """Le scan complet probe HTTP et HTTPS — un cookie HTTP sans Secure est détecté."""
        import respx

        findings = []
        seen = set()

        with respx.mock:
            # HTTPS — pas de cookies
            for path in COOKIE_PROBE_PATHS:
                respx.get(f"https://example.com{path}").mock(
                    return_value=httpx.Response(200)
                )
            # HTTP — pose un cookie
            respx.get("http://example.com/").mock(
                return_value=httpx.Response(
                    200,
                    headers={"set-cookie": "http_sess=val"},
                )
            )
            for path in COOKIE_PROBE_PATHS:
                if path != "/":
                    respx.get(f"http://example.com{path}").mock(
                        return_value=httpx.Response(200)
                    )

            await _check_cookies("http://example.com", findings, seen)

        assert any("http_sess" in f.title for f in findings)


# ===================================================================
# _analyze_cookie — cas limites
# ===================================================================


class TestAnalyzeCookieEdgeCases:
    def test_empty_cookie_string(self):
        """Cookie vide → pas de crash, pas de finding."""
        findings = []
        seen = set()
        _analyze_cookie("", "/", seen, findings)
        # Le nom extrait sera "" — 3 findings pour les attributs manquants
        # Ce n'est pas un "parts vide" car split(";") sur "" donne [""]
        assert isinstance(findings, list)

    def test_cookie_without_value(self):
        """Cookie sans valeur (juste un nom) — ne crash pas."""
        findings = []
        seen = set()
        _analyze_cookie("trackingid", "/", seen, findings)
        assert len(findings) == 3  # Secure, HttpOnly, SameSite manquants
        assert any("trackingid" in f.title for f in findings)

    async def test_multiple_set_cookie_headers(self):
        """Plusieurs Set-Cookie dans une même réponse."""
        import respx

        findings = []
        seen = set()

        with respx.mock:
            # httpx.Response avec plusieurs set-cookie via headers list
            respx.get("https://example.com/").mock(
                return_value=httpx.Response(
                    200,
                    headers=[
                        ("set-cookie", "a=1"),
                        ("set-cookie", "b=2; Secure; HttpOnly; SameSite=Lax"),
                    ],
                )
            )
            for path in COOKIE_PROBE_PATHS:
                if path != "/":
                    respx.get(f"https://example.com{path}").mock(
                        return_value=httpx.Response(200)
                    )

            await _check_cookies("https://example.com", findings, seen)

        # Cookie "a" → 3 findings, cookie "b" → 0 findings
        assert len(findings) == 3
        assert all("a" in f.title or "'a'" in f.title for f in findings)


# ===================================================================
# _check_exposed_files — gestion d'erreurs
# ===================================================================


class TestCheckExposedFilesErrors:
    async def test_baseline_request_exception(self):
        """Exception sur la requête baseline → baseline_len=-1, on continue (L.287-288)."""
        import respx

        findings = []
        with respx.mock:
            # Baseline échoue
            respx.get("https://example.com/a-path-that-should-not-exist-82719").mock(
                side_effect=httpx.ConnectError("timeout")
            )
            # .git/HEAD exposé
            respx.get("https://example.com/.git/HEAD").mock(
                return_value=httpx.Response(200, text="ref: refs/heads/main\n")
            )
            respx.get("https://example.com/.env").mock(
                return_value=httpx.Response(404)
            )
            respx.get("https://example.com/.svn/entries").mock(
                return_value=httpx.Response(404)
            )
            respx.get("https://example.com/web.config").mock(
                return_value=httpx.Response(404)
            )
            respx.get("https://example.com/.well-known/security.txt").mock(
                return_value=httpx.Response(404)
            )
            await _check_exposed_files("https://example.com", findings)

        # .git/HEAD toujours détecté malgré le baseline en erreur
        git_findings = [f for f in findings if "Git" in f.title]
        assert len(git_findings) == 1

    async def test_individual_file_check_exception(self):
        """Exception sur un fichier individuel → continue les autres (L.317-318)."""
        import respx

        findings = []
        with respx.mock:
            respx.get("https://example.com/a-path-that-should-not-exist-82719").mock(
                return_value=httpx.Response(404)
            )
            # .git/HEAD échoue
            respx.get("https://example.com/.git/HEAD").mock(
                side_effect=httpx.ReadTimeout("timeout")
            )
            # .env est exposé
            respx.get("https://example.com/.env").mock(
                return_value=httpx.Response(
                    200,
                    text="SECRET=value",
                    headers={"content-type": "text/plain"},
                )
            )
            respx.get("https://example.com/.svn/entries").mock(
                return_value=httpx.Response(404)
            )
            respx.get("https://example.com/web.config").mock(
                return_value=httpx.Response(404)
            )
            respx.get("https://example.com/.well-known/security.txt").mock(
                return_value=httpx.Response(404)
            )
            await _check_exposed_files("https://example.com", findings)

        # .env détecté malgré l'erreur sur .git/HEAD
        env_findings = [f for f in findings if ".env" in f.title]
        assert len(env_findings) == 1

    async def test_security_txt_check_exception(self):
        """Exception sur security.txt → traité comme absent (L.325-326)."""
        import respx

        findings = []
        with respx.mock:
            respx.get("https://example.com/a-path-that-should-not-exist-82719").mock(
                return_value=httpx.Response(404)
            )
            respx.get("https://example.com/.git/HEAD").mock(
                return_value=httpx.Response(404)
            )
            respx.get("https://example.com/.env").mock(
                return_value=httpx.Response(404)
            )
            respx.get("https://example.com/.svn/entries").mock(
                return_value=httpx.Response(404)
            )
            respx.get("https://example.com/web.config").mock(
                return_value=httpx.Response(404)
            )
            # security.txt échoue
            respx.get("https://example.com/.well-known/security.txt").mock(
                side_effect=httpx.ConnectError("timeout")
            )
            await _check_exposed_files("https://example.com", findings)

        sec_findings = [f for f in findings if "security.txt" in f.title]
        assert len(sec_findings) == 1
        assert sec_findings[0].severity == "info"

    async def test_svn_exposed(self):
        """SVN exposé est détecté (couverture complète des 4 fichiers)."""
        import respx

        findings = []
        with respx.mock:
            respx.get("https://example.com/a-path-that-should-not-exist-82719").mock(
                return_value=httpx.Response(404)
            )
            respx.get("https://example.com/.git/HEAD").mock(
                return_value=httpx.Response(404)
            )
            respx.get("https://example.com/.env").mock(
                return_value=httpx.Response(404)
            )
            respx.get("https://example.com/.svn/entries").mock(
                return_value=httpx.Response(
                    200,
                    text="12\n\ndir\n",
                    headers={"content-type": "text/plain"},
                )
            )
            respx.get("https://example.com/web.config").mock(
                return_value=httpx.Response(404)
            )
            respx.get("https://example.com/.well-known/security.txt").mock(
                return_value=httpx.Response(404)
            )
            await _check_exposed_files("https://example.com", findings)

        svn_findings = [f for f in findings if "SVN" in f.title]
        assert len(svn_findings) == 1
        assert svn_findings[0].severity == "critical"


# ===================================================================
# Full scan — SRI et mixed content via le chemin complet (L.208, L.219)
# ===================================================================


class TestFullScanSRIAndMixedContent:
    async def test_sri_finding_emitted_through_full_scan(self, scanner):
        """Le scan complet détecte le SRI manquant via le HTML parsé (L.207-208)."""
        import respx

        html = '<html><script src="https://cdn.evil.org/lib.js"></script></html>'
        sec_headers = {h["name"]: "value" for h in SECURITY_HEADERS}

        with respx.mock:
            respx.get("https://example.com").mock(
                return_value=httpx.Response(200, headers=sec_headers, text=html)
            )
            respx.get(url__regex=r"https://example\.com/.*").mock(
                return_value=httpx.Response(404)
            )
            respx.get(url__regex=r"http://example\.com.*").mock(
                return_value=httpx.Response(200)
            )

            result = await scanner.scan("example.com")

        sri_findings = [f for f in result.findings if "SRI" in f.title]
        assert len(sri_findings) == 1
        assert sri_findings[0].severity == "medium"
        assert "cdn.evil.org" in sri_findings[0].description

    async def test_mixed_content_finding_emitted_through_full_scan(self, scanner):
        """Le scan complet détecte le mixed content via le HTML parsé (L.218-219)."""
        import respx

        html = '<html><img src="http://insecure.org/img.png"></html>'
        sec_headers = {h["name"]: "value" for h in SECURITY_HEADERS}

        with respx.mock:
            respx.get("https://example.com").mock(
                return_value=httpx.Response(200, headers=sec_headers, text=html)
            )
            respx.get(url__regex=r"https://example\.com/.*").mock(
                return_value=httpx.Response(404)
            )
            respx.get(url__regex=r"http://example\.com.*").mock(
                return_value=httpx.Response(200)
            )

            result = await scanner.scan("example.com")

        mc_findings = [f for f in result.findings if "Mixed content" in f.title]
        assert len(mc_findings) == 1
        assert mc_findings[0].severity == "high"

    async def test_html_parse_exception_silenced(self, scanner):
        """Une exception dans parser.feed() est silencée (L.204-205)."""
        import respx

        sec_headers = {h["name"]: "value" for h in SECURITY_HEADERS}

        with respx.mock:
            respx.get("https://example.com").mock(
                return_value=httpx.Response(200, headers=sec_headers, text="<html></html>")
            )
            respx.get(url__regex=r"https://example\.com/.*").mock(
                return_value=httpx.Response(404)
            )
            respx.get(url__regex=r"http://example\.com.*").mock(
                return_value=httpx.Response(200)
            )

            # Patcher parser.feed pour lever une exception
            with patch.object(_HTMLSecurityParser, "feed", side_effect=Exception("parse error")):
                result = await scanner.scan("example.com")

            # Le scan continue malgré l'erreur de parsing
            assert result.score is not None
            # Pas de SRI/mixed content findings (le parser a échoué)
            sri = [f for f in result.findings if "SRI" in f.title]
            mc = [f for f in result.findings if "Mixed" in f.title]
            assert len(sri) == 0
            assert len(mc) == 0


# ===================================================================
# Full scan — cookies HTTP + HTTPS probing (L.233-235)
# ===================================================================


class TestFullScanCookieProbing:
    async def test_http_and_https_cookie_probing(self, scanner):
        """Le scan complet probe les cookies sur HTTP et HTTPS (L.234-235)."""
        import respx

        sec_headers = {h["name"]: "value" for h in SECURITY_HEADERS}

        with respx.mock:
            # Page principale
            respx.get("https://example.com").mock(
                return_value=httpx.Response(200, headers=sec_headers, text="<html></html>")
            )
            # Exposed files / CORS / security.txt
            respx.get(url__regex=r"https://example\.com/(?!login|signin|sign-in|auth|account|admin).*").mock(
                return_value=httpx.Response(404)
            )
            # HTTPS cookie probing — /login pose un cookie
            for path in COOKIE_PROBE_PATHS:
                if path == "/login":
                    respx.get(f"https://example.com{path}").mock(
                        return_value=httpx.Response(
                            200,
                            headers={"set-cookie": "https_sess=val; Secure; HttpOnly; SameSite=Lax"},
                        )
                    )
                else:
                    respx.get(f"https://example.com{path}").mock(
                        return_value=httpx.Response(200)
                    )
            # HTTP cookie probing — / pose un cookie non sécurisé
            respx.get("http://example.com/").mock(
                return_value=httpx.Response(
                    200,
                    headers={"set-cookie": "http_track=val"},
                )
            )
            for path in COOKIE_PROBE_PATHS:
                if path != "/":
                    respx.get(f"http://example.com{path}").mock(
                        return_value=httpx.Response(200)
                    )

            result = await scanner.scan("example.com")

        # http_track sans Secure/HttpOnly/SameSite → findings
        http_cookie_findings = [f for f in result.findings if "http_track" in f.title]
        assert len(http_cookie_findings) == 3  # Secure, HttpOnly, SameSite

        # https_sess est correct → pas de findings
        https_cookie_findings = [f for f in result.findings if "https_sess" in f.title]
        assert len(https_cookie_findings) == 0
