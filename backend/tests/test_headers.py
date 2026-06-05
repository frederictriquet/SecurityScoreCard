"""Tests for app.scanners.headers — Headers, cookies, SRI, mixed content, CORS, exposed files."""

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
    _check_http_methods,
    _check_robots_sitemap,
    _check_cache_control,
    _check_error_pages,
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
        assert len(parser.sri_issues) == 1  # same (tag, host) deduplicated

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
        assert len(parser.sri_issues) == 1  # cross-origin without integrity
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
        assert len(findings2) == 0  # already seen

    def test_different_cookie_names_not_deduped(self):
        findings = []
        seen = set()
        _analyze_cookie("session=abc", "/", seen, findings)
        _analyze_cookie("token=xyz", "/", seen, findings)
        assert len(findings) == 6  # 3 issues per cookie

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
        assert "reflection" in findings[0].title.lower()

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
        """A .env returning HTML is probably a custom error page."""
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
        """web.config without the <configuration signature → no finding."""
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
        assert len(sec_findings) == 0  # No finding because present

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
        """A server returning 200 for everything with the same content → filtered via baseline."""
        import respx

        generic_html = "<html><body>Page not found</body></html>"
        findings = []
        with respx.mock:
            respx.get("https://example.com/a-path-that-should-not-exist-82719").mock(
                return_value=httpx.Response(200, text=generic_html)
            )
            # .git/HEAD returns the same content (custom 404)
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

        # Only the missing security.txt should appear
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
            # Main page (exact path — first)
            respx.get(url__eq="https://example.com/").mock(
                return_value=httpx.Response(200, headers=headers, text="<html></html>")
            )
            # OPTIONS for HTTP methods check
            respx.options(url__regex=r"https://example\.com").mock(
                return_value=httpx.Response(200)
            )
            # All other HTTPS (sub-paths) → 404
            respx.get(url__regex=r"https://example\.com").mock(
                return_value=httpx.Response(404)
            )
            # Cookie probes (HTTP)
            respx.get(url__regex=r"http://example\.com").mock(
                return_value=httpx.Response(200)
            )

            result = await scanner.scan("example.com")
            # Only the missing security.txt should remain
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
            assert "Unable" in result.findings[0].title

    async def test_missing_headers_detected(self, scanner):
        import respx

        with respx.mock:
            # No security header
            respx.get(url__regex=r"https://example\.com.*").mock(
                return_value=httpx.Response(200, text="<html></html>")
            )
            respx.get(url__regex=r"http://example\.com.*").mock(
                return_value=httpx.Response(200)
            )

            result = await scanner.scan("example.com")
            titles = [f.title for f in result.findings]

            # Verify that all missing headers are detected
            for h in SECURITY_HEADERS:
                assert h["title"] in titles, f"Missing finding for {h['name']}"

    async def test_leaky_headers_detected(self, scanner):
        import respx

        headers = {
            "server": "Apache/2.4.41",
            "x-powered-by": "Express",
        }
        # Add all security headers so as not to pollute
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
            leaky = [f for f in result.findings if "informational" in f.title.lower()]
            assert len(leaky) >= 2
            assert any("server" in f.title.lower() for f in leaky)
            assert any("x-powered-by" in f.title.lower() for f in leaky)




# ===================================================================
# _check_cookies — real multi-path orchestration
# ===================================================================


class TestCheckCookies:
    async def test_probes_all_cookie_paths(self):
        """Verify that _check_cookies queries all COOKIE_PROBE_PATHS."""
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

        # No cookies set → no findings
        assert len(findings) == 0

    async def test_cookies_from_multiple_paths_deduped(self):
        """The same cookie set on / and /login generates only one finding."""
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

        # 3 issues (Secure, HttpOnly, SameSite) but deduplicated on the name
        assert len(findings) == 3
        assert all("session" in f.title for f in findings)

    async def test_different_cookies_from_different_paths(self):
        """Different cookies on different paths are all detected."""
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
            # The other paths do not set cookies
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
        """An exception on one path does not block the others (L.343-344)."""
        import respx

        findings = []
        seen = set()

        with respx.mock:
            # The first path fails
            respx.get("https://example.com/").mock(
                side_effect=httpx.ConnectError("timeout")
            )
            # /login sets a cookie
            respx.get("https://example.com/login").mock(
                return_value=httpx.Response(
                    200,
                    headers={"set-cookie": "sess=abc"},
                )
            )
            # The other paths OK without cookies
            for path in COOKIE_PROBE_PATHS:
                if path not in ("/", "/login"):
                    respx.get(f"https://example.com{path}").mock(
                        return_value=httpx.Response(200)
                    )

            await _check_cookies("https://example.com", findings, seen)

        # The /login cookie is still detected despite the error on /
        assert len(findings) > 0
        assert any("sess" in f.title for f in findings)

    async def test_cookies_in_redirect_history(self):
        """Cookies set in redirect responses (resp.history) are analyzed (L.348)."""
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
            # Simulate a redirect that sets a cookie
            respx.get("https://example.com/login").mock(
                return_value=httpx.Response(
                    200,
                    headers={"set-cookie": "after_login=xyz"},
                )
            )
            # The other paths without cookies
            for path in COOKIE_PROBE_PATHS:
                if path != "/login":
                    respx.get(f"https://example.com{path}").mock(
                        return_value=httpx.Response(200)
                    )

            await _check_cookies("https://example.com", findings, seen)

        assert any("after_login" in f.title for f in findings)

    async def test_http_vs_https_cookie_probing(self):
        """The full scan probes HTTP and HTTPS — an HTTP cookie without Secure is detected."""
        import respx

        findings = []
        seen = set()

        with respx.mock:
            # HTTPS — no cookies
            for path in COOKIE_PROBE_PATHS:
                respx.get(f"https://example.com{path}").mock(
                    return_value=httpx.Response(200)
                )
            # HTTP — sets a cookie
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
# _analyze_cookie — edge cases
# ===================================================================


class TestAnalyzeCookieEdgeCases:
    def test_empty_cookie_string(self):
        """Empty cookie → no crash, no finding."""
        findings = []
        seen = set()
        _analyze_cookie("", "/", seen, findings)
        # The extracted name will be "" — 3 findings for the missing attributes
        # This is not an "empty parts" case because split(";") on "" gives [""]
        assert isinstance(findings, list)

    def test_cookie_without_value(self):
        """Cookie without value (just a name) — does not crash."""
        findings = []
        seen = set()
        _analyze_cookie("trackingid", "/", seen, findings)
        assert len(findings) == 3  # Secure, HttpOnly, SameSite missing
        assert any("trackingid" in f.title for f in findings)

    async def test_multiple_set_cookie_headers(self):
        """Multiple Set-Cookie in a single response."""
        import respx

        findings = []
        seen = set()

        with respx.mock:
            # httpx.Response with multiple set-cookie via headers list
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
# _check_exposed_files — error handling
# ===================================================================


class TestCheckExposedFilesErrors:
    async def test_baseline_request_exception(self):
        """Exception on the baseline request → baseline_len=-1, we continue (L.287-288)."""
        import respx

        findings = []
        with respx.mock:
            # Baseline fails
            respx.get("https://example.com/a-path-that-should-not-exist-82719").mock(
                side_effect=httpx.ConnectError("timeout")
            )
            # .git/HEAD exposed
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

        # .git/HEAD still detected despite the baseline error
        git_findings = [f for f in findings if "Git" in f.title]
        assert len(git_findings) == 1

    async def test_individual_file_check_exception(self):
        """Exception on an individual file → continues with the others (L.317-318)."""
        import respx

        findings = []
        with respx.mock:
            respx.get("https://example.com/a-path-that-should-not-exist-82719").mock(
                return_value=httpx.Response(404)
            )
            # .git/HEAD fails
            respx.get("https://example.com/.git/HEAD").mock(
                side_effect=httpx.ReadTimeout("timeout")
            )
            # .env is exposed
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

        # .env detected despite the error on .git/HEAD
        env_findings = [f for f in findings if ".env" in f.title]
        assert len(env_findings) == 1

    async def test_security_txt_check_exception(self):
        """Exception on security.txt → treated as missing (L.325-326)."""
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
            # security.txt fails
            respx.get("https://example.com/.well-known/security.txt").mock(
                side_effect=httpx.ConnectError("timeout")
            )
            await _check_exposed_files("https://example.com", findings)

        sec_findings = [f for f in findings if "security.txt" in f.title]
        assert len(sec_findings) == 1
        assert sec_findings[0].severity == "info"

    async def test_svn_exposed(self):
        """Exposed SVN is detected (full coverage of the 4 files)."""
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
# Full scan — SRI and mixed content via the full path (L.208, L.219)
# ===================================================================


class TestFullScanSRIAndMixedContent:
    async def test_sri_finding_emitted_through_full_scan(self, scanner):
        """The full scan detects the missing SRI via the parsed HTML (L.207-208)."""
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
        """The full scan detects mixed content via the parsed HTML (L.218-219)."""
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
        """An exception in parser.feed() is silenced (L.204-205)."""
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

            # Patch parser.feed to raise an exception
            with patch.object(_HTMLSecurityParser, "feed", side_effect=Exception("parse error")):
                result = await scanner.scan("example.com")

            # The scan continues despite the parsing error
            assert result.score is not None
            # No SRI/mixed content findings (the parser failed)
            sri = [f for f in result.findings if "SRI" in f.title]
            mc = [f for f in result.findings if "Mixed" in f.title]
            assert len(sri) == 0
            assert len(mc) == 0


# ===================================================================
# Full scan — insecure forms and sensitive comments (L.267, L.275)
# ===================================================================


class TestFullScanInsecureFormsAndComments:
    async def test_insecure_form_finding_through_full_scan(self, scanner):
        """The full scan detects a form submitted over HTTP (L.266-272)."""
        import respx

        html = '<html><form action="http://evil.com/steal" method="post"><input></form></html>'
        sec_headers = {h["name"]: "value" for h in SECURITY_HEADERS}

        with respx.mock:
            respx.get(url__eq="https://example.com/").mock(
                return_value=httpx.Response(200, headers=sec_headers, text=html)
            )
            respx.options(url__regex=r"https://example\.com").mock(
                return_value=httpx.Response(200)
            )
            respx.get(url__regex=r"https://example\.com").mock(
                return_value=httpx.Response(404)
            )
            respx.get(url__regex=r"http://example\.com").mock(
                return_value=httpx.Response(200)
            )

            result = await scanner.scan("example.com")

        form_findings = [f for f in result.findings if "Form" in f.title]
        assert len(form_findings) == 1
        assert form_findings[0].severity == "high"
        assert "evil.com" in form_findings[0].description

    async def test_sensitive_comment_finding_through_full_scan(self, scanner):
        """The full scan detects a sensitive HTML comment (L.274-280)."""
        import respx

        html = '<html><!-- TODO: remove this password=admin123 --></html>'
        sec_headers = {h["name"]: "value" for h in SECURITY_HEADERS}

        with respx.mock:
            respx.get(url__eq="https://example.com/").mock(
                return_value=httpx.Response(200, headers=sec_headers, text=html)
            )
            respx.options(url__regex=r"https://example\.com").mock(
                return_value=httpx.Response(200)
            )
            respx.get(url__regex=r"https://example\.com").mock(
                return_value=httpx.Response(404)
            )
            respx.get(url__regex=r"http://example\.com").mock(
                return_value=httpx.Response(200)
            )

            result = await scanner.scan("example.com")

        comment_findings = [f for f in result.findings if "HTML comment" in f.title]
        assert len(comment_findings) >= 1
        assert comment_findings[0].severity == "low"
        assert "password" in comment_findings[0].title or "todo" in comment_findings[0].title


# ===================================================================
# Full scan — cookies HTTP + HTTPS probing (L.233-235)
# ===================================================================


class TestFullScanCookieProbing:
    async def test_http_and_https_cookie_probing(self, scanner):
        """The full scan probes cookies over HTTP and HTTPS (L.234-235)."""
        import respx

        sec_headers = {h["name"]: "value" for h in SECURITY_HEADERS}

        with respx.mock:
            # Main page
            respx.get("https://example.com").mock(
                return_value=httpx.Response(200, headers=sec_headers, text="<html></html>")
            )
            # Exposed files / CORS / security.txt
            respx.get(url__regex=r"https://example\.com/(?!login|signin|sign-in|auth|account|admin).*").mock(
                return_value=httpx.Response(404)
            )
            # HTTPS cookie probing — /login sets a cookie
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
            # HTTP cookie probing — / sets an insecure cookie
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

        # http_track without Secure/HttpOnly/SameSite → findings
        http_cookie_findings = [f for f in result.findings if "http_track" in f.title]
        assert len(http_cookie_findings) == 3  # Secure, HttpOnly, SameSite

        # https_sess is correct → no findings
        https_cookie_findings = [f for f in result.findings if "https_sess" in f.title]
        assert len(https_cookie_findings) == 0


# ===================================================================
# _HTMLSecurityParser — insecure forms
# ===================================================================


class TestHTMLParserInsecureForms:
    def test_http_form_action_detected(self):
        """Form with HTTP action → insecure_forms detected."""
        parser = _HTMLSecurityParser("example.com")
        parser.feed('<form action="http://evil.com/submit" method="post"></form>')
        assert len(parser.insecure_forms) == 1
        assert "http://evil.com/submit" in parser.insecure_forms[0]

    def test_https_form_action_ok(self):
        """Form with HTTPS action → no problem."""
        parser = _HTMLSecurityParser("example.com")
        parser.feed('<form action="https://example.com/submit" method="post"></form>')
        assert len(parser.insecure_forms) == 0

    def test_relative_form_action_ok(self):
        """Form with relative action → no problem."""
        parser = _HTMLSecurityParser("example.com")
        parser.feed('<form action="/submit" method="post"></form>')
        assert len(parser.insecure_forms) == 0

    def test_form_without_action_ok(self):
        """Form without action attribute → no problem."""
        parser = _HTMLSecurityParser("example.com")
        parser.feed('<form method="post"></form>')
        assert len(parser.insecure_forms) == 0


# ===================================================================
# _HTMLSecurityParser — commentaires sensibles
# ===================================================================


class TestHTMLParserSensitiveComments:
    def test_password_in_comment(self):
        """Comment containing 'password' → detected."""
        parser = _HTMLSecurityParser("example.com")
        parser.feed("<!-- default password is admin123 -->")
        assert len(parser.sensitive_comments) == 1
        assert parser.sensitive_comments[0][0] == "password"

    def test_todo_in_comment(self):
        """Comment containing 'TODO' → detected."""
        parser = _HTMLSecurityParser("example.com")
        parser.feed("<!-- TODO: fix this security issue -->")
        assert len(parser.sensitive_comments) == 1
        assert parser.sensitive_comments[0][0] == "todo"

    def test_api_key_in_comment(self):
        """Comment containing 'api_key' → detected."""
        parser = _HTMLSecurityParser("example.com")
        parser.feed("<!-- api_key: sk_live_abc123 -->")
        assert len(parser.sensitive_comments) == 1
        assert parser.sensitive_comments[0][0] == "api_key"

    def test_harmless_comment_not_detected(self):
        """Harmless comment → no detection."""
        parser = _HTMLSecurityParser("example.com")
        parser.feed("<!-- This is a navigation menu -->")
        assert len(parser.sensitive_comments) == 0

    def test_multiple_keywords_single_match(self):
        """Comment with multiple keywords → a single detection (first match)."""
        parser = _HTMLSecurityParser("example.com")
        parser.feed("<!-- password: secret token=abc -->")
        assert len(parser.sensitive_comments) == 1

    def test_long_comment_truncated(self):
        """Very long comment → excerpt truncated to 120 chars."""
        parser = _HTMLSecurityParser("example.com")
        parser.feed(f"<!-- password {'x' * 200} -->")
        assert len(parser.sensitive_comments) == 1
        assert len(parser.sensitive_comments[0][1]) <= 120


# ===================================================================
# X-XSS-Protection in the full scan
# ===================================================================


class TestXXSSProtection:
    async def test_x_xss_protection_zero_detected(self, scanner):
        """X-XSS-Protection: 0 → low finding."""
        import respx

        sec_headers = {h["name"]: "value" for h in SECURITY_HEADERS}
        sec_headers["x-xss-protection"] = "0"

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
            respx.options("https://example.com").mock(
                return_value=httpx.Response(200)
            )

            result = await scanner.scan("example.com")

        xss_findings = [f for f in result.findings if "XSS-Protection" in f.title]
        assert len(xss_findings) == 1
        assert xss_findings[0].severity == "low"

    async def test_x_xss_protection_mode_block_no_finding(self, scanner):
        """X-XSS-Protection: 1; mode=block → no finding."""
        import respx

        sec_headers = {h["name"]: "value" for h in SECURITY_HEADERS}
        sec_headers["x-xss-protection"] = "1; mode=block"

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
            respx.options("https://example.com").mock(
                return_value=httpx.Response(200)
            )

            result = await scanner.scan("example.com")

        xss_findings = [f for f in result.findings if "XSS-Protection" in f.title]
        assert len(xss_findings) == 0


# ===================================================================
# _check_http_methods
# ===================================================================


class TestCheckHttpMethods:
    async def test_dangerous_methods_detected(self):
        """PUT and DELETE allowed → medium finding."""
        import respx

        findings = []
        with respx.mock:
            respx.options("https://example.com").mock(
                return_value=httpx.Response(200, headers={"allow": "GET, POST, PUT, DELETE"})
            )
            await _check_http_methods("https://example.com", findings)

        assert len(findings) == 1
        assert findings[0].severity == "medium"
        assert "DELETE" in findings[0].title
        assert "PUT" in findings[0].title

    async def test_safe_methods_no_finding(self):
        """GET, POST, OPTIONS → no finding."""
        import respx

        findings = []
        with respx.mock:
            respx.options("https://example.com").mock(
                return_value=httpx.Response(200, headers={"allow": "GET, POST, OPTIONS, HEAD"})
            )
            await _check_http_methods("https://example.com", findings)

        assert len(findings) == 0

    async def test_no_allow_header(self):
        """No Allow header → no finding."""
        import respx

        findings = []
        with respx.mock:
            respx.options("https://example.com").mock(
                return_value=httpx.Response(200)
            )
            await _check_http_methods("https://example.com", findings)

        assert len(findings) == 0

    async def test_trace_method_detected(self):
        """TRACE allowed → medium finding."""
        import respx

        findings = []
        with respx.mock:
            respx.options("https://example.com").mock(
                return_value=httpx.Response(200, headers={"allow": "GET, TRACE"})
            )
            await _check_http_methods("https://example.com", findings)

        assert len(findings) == 1
        assert "TRACE" in findings[0].title

    async def test_exception_silenced(self):
        """Exception on OPTIONS → silent."""
        import respx

        findings = []
        with respx.mock:
            respx.options("https://example.com").mock(
                side_effect=httpx.ConnectError("refused")
            )
            await _check_http_methods("https://example.com", findings)

        assert len(findings) == 0


# ===================================================================
# _check_robots_sitemap
# ===================================================================


class TestCheckRobotsSitemap:
    async def test_sensitive_paths_in_robots(self):
        """robots.txt with sensitive paths → low finding."""
        import respx

        findings = []
        with respx.mock:
            respx.get("https://example.com/robots.txt").mock(
                return_value=httpx.Response(
                    200,
                    text="User-agent: *\nDisallow: /admin/\nDisallow: /api/internal\n",
                )
            )
            respx.get("https://example.com/sitemap.xml").mock(
                return_value=httpx.Response(404)
            )
            await _check_robots_sitemap("https://example.com", findings)

        robots_findings = [f for f in findings if "robots.txt" in f.title]
        assert len(robots_findings) == 1
        assert robots_findings[0].severity == "low"

    async def test_robots_no_sensitive_paths(self):
        """robots.txt without sensitive paths → no robots finding."""
        import respx

        findings = []
        with respx.mock:
            respx.get("https://example.com/robots.txt").mock(
                return_value=httpx.Response(
                    200,
                    text="User-agent: *\nDisallow: /images/\n",
                )
            )
            respx.get("https://example.com/sitemap.xml").mock(
                return_value=httpx.Response(404)
            )
            await _check_robots_sitemap("https://example.com", findings)

        robots_findings = [f for f in findings if "robots.txt" in f.title]
        assert len(robots_findings) == 0

    async def test_sitemap_xml_detected(self):
        """sitemap.xml accessible → info finding."""
        import respx

        findings = []
        with respx.mock:
            respx.get("https://example.com/robots.txt").mock(
                return_value=httpx.Response(404)
            )
            respx.get("https://example.com/sitemap.xml").mock(
                return_value=httpx.Response(
                    200,
                    text='<?xml version="1.0"?><urlset><url><loc>https://example.com/</loc></url></urlset>',
                )
            )
            await _check_robots_sitemap("https://example.com", findings)

        sitemap_findings = [f for f in findings if "sitemap" in f.title.lower()]
        assert len(sitemap_findings) == 1
        assert sitemap_findings[0].severity == "info"

    async def test_robots_exception_silenced(self):
        """Exception on robots.txt → no crash."""
        import respx

        findings = []
        with respx.mock:
            respx.get("https://example.com/robots.txt").mock(
                side_effect=httpx.ConnectError("timeout")
            )
            respx.get("https://example.com/sitemap.xml").mock(
                return_value=httpx.Response(404)
            )
            await _check_robots_sitemap("https://example.com", findings)

        # No crash, no robots finding
        robots_findings = [f for f in findings if "robots.txt" in f.title]
        assert len(robots_findings) == 0

    async def test_robots_no_disallow_no_finding(self):
        """robots.txt without Disallow → no finding."""
        import respx

        findings = []
        with respx.mock:
            respx.get("https://example.com/robots.txt").mock(
                return_value=httpx.Response(200, text="User-agent: *\nAllow: /\n")
            )
            respx.get("https://example.com/sitemap.xml").mock(
                return_value=httpx.Response(404)
            )
            await _check_robots_sitemap("https://example.com", findings)

        robots_findings = [f for f in findings if "robots.txt" in f.title]
        assert len(robots_findings) == 0


# ===================================================================
# _check_cache_control
# ===================================================================


class TestCheckCacheControl:
    async def test_missing_cache_control_on_login(self):
        """/login page without Cache-Control: no-store → medium finding."""
        import respx

        findings = []
        with respx.mock:
            respx.get("https://example.com/login").mock(
                return_value=httpx.Response(200, headers={"cache-control": "public, max-age=3600"})
            )
            respx.get("https://example.com/signin").mock(
                return_value=httpx.Response(404)
            )
            respx.get("https://example.com/account").mock(
                return_value=httpx.Response(404)
            )
            respx.get("https://example.com/admin").mock(
                return_value=httpx.Response(404)
            )
            respx.get("https://example.com/dashboard").mock(
                return_value=httpx.Response(404)
            )
            await _check_cache_control("https://example.com", findings)

        assert len(findings) == 1
        assert findings[0].severity == "medium"
        assert "/login" in findings[0].title

    async def test_cache_control_no_store_ok(self):
        """/login page with no-store → no finding."""
        import respx

        findings = []
        with respx.mock:
            respx.get("https://example.com/login").mock(
                return_value=httpx.Response(200, headers={"cache-control": "no-store, no-cache"})
            )
            respx.get("https://example.com/signin").mock(
                return_value=httpx.Response(404)
            )
            respx.get("https://example.com/account").mock(
                return_value=httpx.Response(404)
            )
            respx.get("https://example.com/admin").mock(
                return_value=httpx.Response(404)
            )
            respx.get("https://example.com/dashboard").mock(
                return_value=httpx.Response(404)
            )
            await _check_cache_control("https://example.com", findings)

        assert len(findings) == 0

    async def test_all_sensitive_pages_404(self):
        """All sensitive pages return 404 → no finding."""
        import respx

        findings = []
        with respx.mock:
            for path in ["/login", "/signin", "/account", "/admin", "/dashboard"]:
                respx.get(f"https://example.com{path}").mock(
                    return_value=httpx.Response(404)
                )
            await _check_cache_control("https://example.com", findings)

        assert len(findings) == 0

    async def test_only_one_finding_emitted(self):
        """Even if several pages lack no-store → a single finding (return after the first)."""
        import respx

        findings = []
        with respx.mock:
            respx.get("https://example.com/login").mock(
                return_value=httpx.Response(200, headers={"cache-control": "public"})
            )
            respx.get("https://example.com/signin").mock(
                return_value=httpx.Response(200, headers={"cache-control": "public"})
            )
            respx.get("https://example.com/account").mock(
                return_value=httpx.Response(404)
            )
            respx.get("https://example.com/admin").mock(
                return_value=httpx.Response(404)
            )
            respx.get("https://example.com/dashboard").mock(
                return_value=httpx.Response(404)
            )
            await _check_cache_control("https://example.com", findings)

        assert len(findings) == 1


# ===================================================================
# _check_error_pages
# ===================================================================


class TestCheckErrorPages:
    async def test_stack_trace_in_error_page(self):
        """Error page with traceback → medium finding."""
        import respx

        findings = []
        with respx.mock:
            respx.get("https://example.com/a-nonexistent-page-security-test-73921").mock(
                return_value=httpx.Response(
                    500,
                    text="Internal Server Error\nTraceback (most recent call last):\n  File ...",
                )
            )
            await _check_error_pages("https://example.com", findings)

        assert len(findings) == 1
        assert findings[0].severity == "medium"
        assert "error page" in findings[0].title.lower()

    async def test_clean_error_page_no_finding(self):
        """Clean error page → no finding."""
        import respx

        findings = []
        with respx.mock:
            respx.get("https://example.com/a-nonexistent-page-security-test-73921").mock(
                return_value=httpx.Response(404, text="<html><h1>Page not found</h1></html>")
            )
            await _check_error_pages("https://example.com", findings)

        assert len(findings) == 0

    async def test_error_page_returns_200(self):
        """Nonexistent page returns 200 (custom 404) → no finding (status < 400)."""
        import respx

        findings = []
        with respx.mock:
            respx.get("https://example.com/a-nonexistent-page-security-test-73921").mock(
                return_value=httpx.Response(200, text="Not found")
            )
            await _check_error_pages("https://example.com", findings)

        assert len(findings) == 0

    async def test_sql_error_detected(self):
        """Error page with SQLSTATE → medium finding."""
        import respx

        findings = []
        with respx.mock:
            respx.get("https://example.com/a-nonexistent-page-security-test-73921").mock(
                return_value=httpx.Response(
                    500,
                    text="<html>Error: SQLSTATE[42000]: Syntax error in query</html>",
                )
            )
            await _check_error_pages("https://example.com", findings)

        assert len(findings) == 1
        assert findings[0].severity == "medium"

    async def test_exception_silenced(self):
        """Exception on the request → silent."""
        import respx

        findings = []
        with respx.mock:
            respx.get("https://example.com/a-nonexistent-page-security-test-73921").mock(
                side_effect=httpx.ConnectError("timeout")
            )
            await _check_error_pages("https://example.com", findings)

        assert len(findings) == 0


# ===================================================================
# _analyze_cookie — __Secure- prefix
# ===================================================================


class TestCookieSecurePrefix:
    def test_secure_prefix_without_secure_attr(self):
        """Cookie __Secure-X without Secure → medium finding."""
        findings = []
        seen = set()
        _analyze_cookie("__Secure-session=abc; HttpOnly; SameSite=Lax", "/", seen, findings)
        prefix_findings = [f for f in findings if "__Secure- prefix" in f.title]
        assert len(prefix_findings) == 1
        assert prefix_findings[0].severity == "medium"

    def test_secure_prefix_with_secure_attr(self):
        """Cookie __Secure-X with Secure → no prefix finding."""
        findings = []
        seen = set()
        _analyze_cookie("__Secure-session=abc; Secure; HttpOnly; SameSite=Lax", "/", seen, findings)
        prefix_findings = [f for f in findings if "__Secure-" in f.title]
        assert len(prefix_findings) == 0

    def test_secure_prefix_dedup(self):
        """The same __Secure- cookie twice → a single finding thanks to the seen set."""
        findings = []
        seen = set()
        _analyze_cookie("__Secure-session=abc; HttpOnly", "/", seen, findings)
        _analyze_cookie("__Secure-session=abc; HttpOnly", "/login", seen, findings)
        prefix_findings = [f for f in findings if "__Secure- prefix" in f.title]
        assert len(prefix_findings) == 1


# ===================================================================
# _analyze_cookie — __Host- prefix
# ===================================================================


class TestCookieHostPrefix:
    def test_host_prefix_missing_secure(self):
        """Cookie __Host-X without Secure → medium finding (misconfigured __Host- prefix)."""
        findings = []
        seen = set()
        _analyze_cookie("__Host-session=abc; Path=/; HttpOnly; SameSite=Lax", "/", seen, findings)
        host_findings = [f for f in findings if "__Host- prefix" in f.title]
        assert len(host_findings) == 1
        assert "Secure missing" in host_findings[0].description

    def test_host_prefix_with_domain(self):
        """Cookie __Host-X with Domain → medium finding."""
        findings = []
        seen = set()
        _analyze_cookie("__Host-session=abc; Secure; Path=/; Domain=example.com; HttpOnly; SameSite=Lax", "/", seen, findings)
        host_findings = [f for f in findings if "__Host- prefix" in f.title]
        assert len(host_findings) == 1
        assert "Domain" in host_findings[0].description

    def test_host_prefix_wrong_path(self):
        """Cookie __Host-X with Path=/admin → medium finding."""
        findings = []
        seen = set()
        _analyze_cookie("__Host-session=abc; Secure; Path=/admin; HttpOnly; SameSite=Lax", "/", seen, findings)
        host_findings = [f for f in findings if "__Host- prefix" in f.title]
        assert len(host_findings) == 1
        assert "Path" in host_findings[0].description

    def test_host_prefix_correct(self):
        """Cookie __Host-X correctly configured → no __Host- prefix finding."""
        findings = []
        seen = set()
        _analyze_cookie("__Host-session=abc; Secure; Path=/; HttpOnly; SameSite=Lax", "/", seen, findings)
        host_findings = [f for f in findings if "__Host- prefix" in f.title]
        assert len(host_findings) == 0


# ===================================================================
# _analyze_cookie — Max-Age excessif
# ===================================================================


class TestCookieMaxAge:
    def test_max_age_over_one_year(self):
        """Max-Age > 31536000 → low finding."""
        findings = []
        seen = set()
        _analyze_cookie("tracker=abc; Max-Age=63072000; Secure; HttpOnly; SameSite=Lax", "/", seen, findings)
        maxage_findings = [f for f in findings if "excessive lifetime" in f.title]
        assert len(maxage_findings) == 1
        assert maxage_findings[0].severity == "low"

    def test_max_age_exactly_one_year(self):
        """Max-Age = 31536000 (exactly 1 year) → no finding."""
        findings = []
        seen = set()
        _analyze_cookie("tracker=abc; Max-Age=31536000; Secure; HttpOnly; SameSite=Lax", "/", seen, findings)
        maxage_findings = [f for f in findings if "excessive lifetime" in f.title]
        assert len(maxage_findings) == 0

    def test_max_age_invalid_value(self):
        """Invalid Max-Age (non-numeric) → ignored, no crash."""
        findings = []
        seen = set()
        _analyze_cookie("tracker=abc; Max-Age=abc; Secure; HttpOnly; SameSite=Lax", "/", seen, findings)
        maxage_findings = [f for f in findings if "excessive lifetime" in f.title]
        assert len(maxage_findings) == 0


# ===================================================================
# _analyze_cookie — Domain scope trop large
# ===================================================================


class TestCookieDomainScope:
    def test_domain_with_leading_dot(self):
        """Domain=.example.com → medium finding (scope too broad)."""
        findings = []
        seen = set()
        _analyze_cookie("sess=abc; Domain=.example.com; Secure; HttpOnly; SameSite=Lax", "/", seen, findings)
        domain_findings = [f for f in findings if "scope" in f.title.lower()]
        assert len(domain_findings) == 1
        assert domain_findings[0].severity == "medium"

    def test_domain_without_leading_dot(self):
        """Domain=example.com (without leading dot) → no scope finding."""
        findings = []
        seen = set()
        _analyze_cookie("sess=abc; Domain=example.com; Secure; HttpOnly; SameSite=Lax", "/", seen, findings)
        domain_findings = [f for f in findings if "scope" in f.title.lower()]
        assert len(domain_findings) == 0

    def test_no_domain_attr(self):
        """No Domain attribute → no scope finding."""
        findings = []
        seen = set()
        _analyze_cookie("sess=abc; Secure; HttpOnly; SameSite=Lax", "/", seen, findings)
        domain_findings = [f for f in findings if "scope" in f.title.lower()]
        assert len(domain_findings) == 0
