import asyncio
import logging

import httpx
from html.parser import HTMLParser
from urllib.parse import urlparse

from app.scanners.base import BaseScanner, ScanResult, FindingData

logger = logging.getLogger(__name__)

USER_AGENT = "SecurityScoreCard-Scanner/1.0 (passive security audit)"
_CLIENT_DEFAULTS = {
    "follow_redirects": True,
    "timeout": 10,
    "verify": False,
    "headers": {"User-Agent": USER_AGENT},
}

SECURITY_HEADERS = [
    {
        "name": "strict-transport-security",
        "title": "HSTS missing",
        "severity": "high",
        "description": "The Strict-Transport-Security header enforces HTTPS but is not present.",
        "remediation": "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains",
    },
    {
        "name": "content-security-policy",
        "title": "CSP missing",
        "severity": "medium",
        "description": "The Content-Security-Policy header protects against XSS injections but is not present.",
        "remediation": "Set a CSP policy suited to your application.",
    },
    {
        "name": "x-frame-options",
        "title": "X-Frame-Options missing",
        "severity": "medium",
        "description": "Without this header, the page can be embedded in an iframe (clickjacking risk).",
        "remediation": "Add: X-Frame-Options: DENY or SAMEORIGIN",
    },
    {
        "name": "x-content-type-options",
        "title": "X-Content-Type-Options missing",
        "severity": "low",
        "description": "Without this header, the browser can guess the MIME type (MIME sniffing).",
        "remediation": "Add: X-Content-Type-Options: nosniff",
    },
    {
        "name": "referrer-policy",
        "title": "Referrer-Policy missing",
        "severity": "low",
        "description": "Without Referrer-Policy, full URLs may be sent to third parties.",
        "remediation": "Add: Referrer-Policy: strict-origin-when-cross-origin",
    },
    {
        "name": "permissions-policy",
        "title": "Permissions-Policy missing",
        "severity": "low",
        "description": "Without Permissions-Policy, access to browser APIs (camera, microphone...) is not restricted.",
        "remediation": "Add a Permissions-Policy header suited to your usage.",
    },
    {
        "name": "cross-origin-opener-policy",
        "title": "Cross-Origin-Opener-Policy (COOP) missing",
        "severity": "low",
        "description": "Without COOP, the page can be exploited via cross-origin attacks (Spectre, window.opener).",
        "remediation": "Add: Cross-Origin-Opener-Policy: same-origin",
    },
    {
        "name": "cross-origin-embedder-policy",
        "title": "Cross-Origin-Embedder-Policy (COEP) missing",
        "severity": "low",
        "description": "Without COEP, the page cannot enable cross-origin isolation (SharedArrayBuffer, etc.).",
        "remediation": "Add: Cross-Origin-Embedder-Policy: require-corp",
    },
    {
        "name": "cross-origin-resource-policy",
        "title": "Cross-Origin-Resource-Policy (CORP) missing",
        "severity": "low",
        "description": "Without CORP, resources can be loaded by any site (data leak risk).",
        "remediation": "Add: Cross-Origin-Resource-Policy: same-origin",
    },
]

LEAKY_HEADERS = ["server", "x-powered-by", "x-aspnet-version", "x-aspnetmvc-version"]

# Pages likely to set session cookies
COOKIE_PROBE_PATHS = ["/", "/login", "/signin", "/sign-in", "/auth", "/account", "/admin"]

# Sensitive files whose exposure is critical
EXPOSED_FILES = [
    ("/.git/HEAD", "ref: ", "critical",
     "Git repository exposed (.git/)",
     "The Git repository is publicly accessible. An attacker can download the source code and history.",
     "Block access to the .git directory in the web server configuration."),
    ("/.env", None, "critical",
     ".env file exposed",
     "The environment file is accessible. It may contain passwords, API keys and secrets.",
     "Block access to dotenv files and exclude them from deployment."),
    ("/.svn/entries", None, "critical",
     "SVN repository exposed (.svn/)",
     "The Subversion repository is publicly accessible.",
     "Block access to the .svn directory."),
    ("/web.config", "<configuration", "high",
     "web.config file exposed",
     "The IIS configuration is accessible and may contain secrets.",
     "Block access to the web.config file."),
    # Backup files (6.5)
    ("/.htpasswd", None, "critical",
     ".htpasswd file exposed",
     "The Apache password file is publicly accessible.",
     "Block access to .ht* files in the server configuration."),
    ("/backup.sql", None, "critical",
     "SQL dump accessible (backup.sql)",
     "A database backup file is exposed. It may contain all of the site's data.",
     "Remove backup files from the public web directory."),
    ("/dump.sql", None, "critical",
     "SQL dump accessible (dump.sql)",
     "A database backup file is exposed.",
     "Remove backup files from the public web directory."),
    ("/database.sql", None, "critical",
     "SQL dump accessible (database.sql)",
     "A database backup file is exposed.",
     "Remove backup files from the public web directory."),
]


class _HTMLSecurityParser(HTMLParser):
    """Parses the HTML to detect SRI and mixed content issues."""

    def __init__(self, origin_host: str) -> None:
        super().__init__()
        self.origin_host = origin_host
        self.sri_issues: list[tuple[str, str, str]] = []  # (tag, url, host)
        self.mixed_content: list[tuple[str, str]] = []  # (tag, url)
        self.insecure_forms: list[str] = []  # action URLs over HTTP
        self.sensitive_comments: list[tuple[str, str]] = []  # (keyword, excerpt)
        self._seen_sri: set[tuple[str, str]] = set()
        self._seen_mixed: set[str] = set()

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        d = dict(attrs)

        # Determine the resource URL
        url = ""
        if tag == "script":
            url = d.get("src") or ""
        elif tag == "link" and "stylesheet" in (d.get("rel") or "").lower():
            url = d.get("href") or ""

        if url:
            parsed = urlparse(url)
            host = parsed.netloc

            # SRI: cross-origin resource without integrity
            if host and host != self.origin_host and not d.get("integrity"):
                key = (tag, host)
                if key not in self._seen_sri:
                    self._seen_sri.add(key)
                    self.sri_issues.append((tag, url, host))

            # Mixed content: HTTP resource on an HTTPS page
            if parsed.scheme == "http" and host:
                mk = f"{tag}:{host}"
                if mk not in self._seen_mixed:
                    self._seen_mixed.add(mk)
                    self.mixed_content.append((tag, url))

        # Mixed content for the other elements (img, iframe, etc.)
        if tag in ("img", "iframe", "video", "audio", "source", "embed", "object"):
            src = d.get("src") or ""
            if src:
                p = urlparse(src)
                if p.scheme == "http" and p.netloc:
                    mk = f"{tag}:{p.netloc}"
                    if mk not in self._seen_mixed:
                        self._seen_mixed.add(mk)
                        self.mixed_content.append((tag, src))

        # Forms submitted over HTTP
        if tag == "form":
            action = d.get("action") or ""
            if action:
                p = urlparse(action)
                if p.scheme == "http" and p.netloc:
                    self.insecure_forms.append(action)

    def handle_comment(self, data: str) -> None:
        _SENSITIVE_KW = [
            "password", "secret", "api_key", "apikey", "api-key", "token",
            "todo", "fixme", "hack", "bug", "debug", "credentials", "private_key",
        ]
        lower = data.lower()
        for kw in _SENSITIVE_KW:
            if kw in lower:
                self.sensitive_comments.append((kw, data.strip()[:120]))
                break


class HeadersScanner(BaseScanner):
    name = "headers"
    weight = 0.15

    async def scan(self, domain: str) -> ScanResult:
        findings: list[FindingData] = []
        base_url = f"https://{domain}"

        # verify=False: the TLS scanner handles certificate issues separately;
        # here we want to analyze headers and cookies even if the cert is expired/invalid.
        try:
            async with httpx.AsyncClient(**_CLIENT_DEFAULTS) as client:
                response = await client.get(base_url)
                headers = {k.lower(): v for k, v in response.headers.items()}
        except Exception as exc:
            findings.append(FindingData(
                severity="high",
                title="Unable to retrieve HTTP headers",
                description=f"The GET request to {base_url} failed: {exc}",
            ))
            return ScanResult.from_findings(findings)

        # Check security headers
        for check in SECURITY_HEADERS:
            if check["name"] not in headers:
                findings.append(FindingData(
                    severity=check["severity"],
                    title=check["title"],
                    description=check["description"],
                    remediation=check["remediation"],
                ))

        # Exposed informational headers
        for header in LEAKY_HEADERS:
            if header in headers:
                findings.append(FindingData(
                    severity="info",
                    title=f"Informational header exposed: {header}",
                    description=f"The value '{headers[header]}' discloses information about the technical stack.",
                    remediation=f"Remove or mask the {header} header.",
                ))

        # HTML analysis: SRI + Mixed Content
        parser = _HTMLSecurityParser(domain)
        try:
            parser.feed(response.text)
        except ValueError as exc:
            # Hostile/malformed markup (e.g. an unparseable URL hitting
            # urlparse) must not abort the header analysis.
            logger.debug("headers: HTML parsing failed for %s: %s", base_url, exc)

        for tag, url, host in parser.sri_issues:
            findings.append(FindingData(
                severity="medium",
                title=f"SRI missing on an external resource ({tag})",
                description=f"The resource loaded from '{host}' has no integrity attribute.",
                remediation=(
                    f"Add integrity=\"sha384-<hash>\" on the {tag} tag pointing to {url}. "
                    "Generate the hash with: openssl dgst -sha384 -binary file.js | openssl base64 -A"
                ),
            ))

        for tag, url in parser.mixed_content:
            findings.append(FindingData(
                severity="high",
                title=f"Mixed content: HTTP resource ({tag})",
                description=f"The resource '{url}' is loaded over HTTP on an HTTPS page, exposing the content to interception.",
                remediation="Load all resources over HTTPS.",
            ))

        for action_url in parser.insecure_forms:
            findings.append(FindingData(
                severity="high",
                title="Form submitted over HTTP",
                description=f"A form sends data to '{action_url}' over cleartext HTTP.",
                remediation="Use an HTTPS URL for the form's action attribute.",
            ))

        for kw, excerpt in parser.sensitive_comments[:5]:
            findings.append(FindingData(
                severity="low",
                title=f"Sensitive HTML comment (keyword: {kw})",
                description=f"An HTML comment contains '{kw}': \"{excerpt}\"",
                remediation="Remove comments containing sensitive information before going to production.",
            ))

        # X-XSS-Protection deprecated but reported if disabled
        xss_prot = headers.get("x-xss-protection", "")
        if xss_prot.strip() == "0":
            findings.append(FindingData(
                severity="low",
                title="X-XSS-Protection explicitly disabled (0)",
                description="The X-XSS-Protection header is set to 0, removing the XSS protection of older browsers.",
                remediation="Remove the header or configure it to '1; mode=block'.",
            ))

        # Parallel checks
        await asyncio.gather(
            _check_cors(base_url, findings),
            _check_exposed_files(base_url, findings),
            _check_http_methods(base_url, findings),
            _check_robots_sitemap(base_url, findings),
            _check_cache_control(base_url, findings),
            _check_error_pages(base_url, findings),
        )

        # Cookies (HTTP + HTTPS)
        seen_issues: set[str] = set()
        await _check_cookies(f"http://{domain}", findings, seen_issues)
        await _check_cookies(base_url, findings, seen_issues)

        return ScanResult.from_findings(findings)


# --- Helper functions ---


async def _check_cors(base_url: str, findings: list) -> None:
    """Tests whether the server reflects an arbitrary Origin or uses *."""
    try:
        async with httpx.AsyncClient(**_CLIENT_DEFAULTS) as client:
            resp = await client.get(base_url, headers={"Origin": "https://evil.example.com"})
            acao = resp.headers.get("access-control-allow-origin", "")
            acac = resp.headers.get("access-control-allow-credentials", "").lower()

            if acao == "*":
                findings.append(FindingData(
                    severity="medium",
                    title="CORS too permissive (Access-Control-Allow-Origin: *)",
                    description="The server allows cross-origin requests from any domain.",
                    remediation="Restrict Access-Control-Allow-Origin to the allowed domains.",
                ))
            elif acao == "https://evil.example.com":
                if acac == "true":
                    findings.append(FindingData(
                        severity="high",
                        title="CORS: Origin reflection with credentials",
                        description="The server reflects any Origin and allows credentials. "
                                    "This enables cross-origin data theft.",
                        remediation="Do not reflect the Origin without validation. Maintain a whitelist.",
                    ))
                else:
                    findings.append(FindingData(
                        severity="medium",
                        title="CORS: Origin reflection",
                        description="The server reflects any Origin in Access-Control-Allow-Origin.",
                        remediation="Validate the Origin against a whitelist before reflecting it.",
                    ))
    except httpx.HTTPError as exc:
        logger.debug("headers: CORS check failed for %s: %s", base_url, exc)


async def _check_exposed_files(base_url: str, findings: list) -> None:
    """Checks the accessibility of sensitive files and the presence of security.txt."""
    security_txt_found = False

    async with httpx.AsyncClient(**_CLIENT_DEFAULTS) as client:
        # 404 baseline to filter out custom 404s that return 200
        try:
            baseline = await client.get(f"{base_url}/a-path-that-should-not-exist-82719")
            baseline_len = len(baseline.text)
        except httpx.HTTPError as exc:
            logger.debug("headers: 404 baseline request failed for %s: %s", base_url, exc)
            baseline_len = -1

        for path, signature, severity, title, desc, remed in EXPOSED_FILES:
            try:
                resp = await client.get(f"{base_url}{path}")
                if resp.status_code != 200:
                    continue

                text = resp.text[:2000]
                content_type = resp.headers.get("content-type", "")

                # Filter out custom 404s (same size as the baseline)
                if baseline_len > 0 and abs(len(resp.text) - baseline_len) < 100:
                    continue

                # If a signature is required, check its presence
                if signature and signature not in text:
                    continue

                # Without a signature, ignore HTML responses (probably an error page)
                if not signature and "text/html" in content_type:
                    continue

                findings.append(FindingData(
                    severity=severity,
                    title=title,
                    description=desc,
                    remediation=remed,
                ))
            except httpx.HTTPError as exc:
                logger.debug("headers: exposed-file probe %s failed for %s: %s", path, base_url, exc)
                continue

        # security.txt
        try:
            resp = await client.get(f"{base_url}/.well-known/security.txt")
            if resp.status_code == 200 and "contact:" in resp.text.lower():
                security_txt_found = True
        except httpx.HTTPError as exc:
            logger.debug("headers: security.txt probe failed for %s: %s", base_url, exc)

    if not security_txt_found:
        findings.append(FindingData(
            severity="info",
            title="security.txt absent",
            description="No security.txt file found. This file helps security researchers report vulnerabilities.",
            remediation="Create /.well-known/security.txt according to RFC 9116 (Contact, Expires, etc.).",
        ))


async def _check_cookies(base_url: str, findings: list, seen_issues: set[str]) -> None:
    """Probes several common paths and analyzes the Set-Cookie attributes."""
    async with httpx.AsyncClient(**_CLIENT_DEFAULTS) as client:
        for path in COOKIE_PROBE_PATHS:
            try:
                resp = await client.get(f"{base_url}{path}")
            except httpx.HTTPError as exc:
                logger.debug("headers: cookie probe %s failed for %s: %s", path, base_url, exc)
                continue

            for r in [*resp.history, resp]:
                for raw in r.headers.get_list("set-cookie"):
                    _analyze_cookie(raw, path, seen_issues, findings)


def _analyze_cookie(raw: str, path: str, seen: set, findings: list) -> None:
    """Parses a raw Set-Cookie and checks Secure, HttpOnly, SameSite."""
    parts = [p.strip() for p in raw.split(";")]
    if not parts:
        return

    name = parts[0].split("=")[0].strip() if "=" in parts[0] else parts[0].strip()
    attrs = {p.split("=")[0].strip().lower() for p in parts[1:]}
    attr_map = {}
    for p in parts[1:]:
        k, _, v = p.strip().partition("=")
        attr_map[k.strip().lower()] = v.strip().lower()

    # __Secure- prefix (4.4)
    if name.startswith("__Secure-") and "secure" not in attrs:
        issue_key = f"prefix-secure:{name}"
        if issue_key not in seen:
            seen.add(issue_key)
            findings.append(FindingData(
                severity="medium",
                title=f"Cookie '{name}': __Secure- prefix without Secure attribute",
                description="Cookies with the __Secure- prefix must have the Secure attribute.",
                remediation="Add the Secure attribute or remove the __Secure- prefix.",
            ))

    # __Host- prefix (4.4)
    if name.startswith("__Host-"):
        problems = []
        if "secure" not in attrs:
            problems.append("Secure missing")
        if attr_map.get("path", "") != "/":
            problems.append("Path must be /")
        if "domain" in attr_map:
            problems.append("Domain must not be set")
        if problems:
            issue_key = f"prefix-host:{name}"
            if issue_key not in seen:
                seen.add(issue_key)
                findings.append(FindingData(
                    severity="medium",
                    title=f"Cookie '{name}': __Host- prefix misconfigured",
                    description=f"Issues: {', '.join(problems)}. __Host- cookies require Secure, Path=/ and no Domain.",
                    remediation="Fix the cookie attributes according to the __Host- prefix requirements.",
                ))

    # Excessive Max-Age > 1 year (4.5)
    max_age_str = attr_map.get("max-age", "")
    if max_age_str:
        try:
            max_age = int(max_age_str)
            if max_age > 31536000:
                issue_key = f"maxage:{name}"
                if issue_key not in seen:
                    seen.add(issue_key)
                    days = max_age // 86400
                    findings.append(FindingData(
                        severity="low",
                        title=f"Cookie '{name}': excessive lifetime ({days} days)",
                        description=f"The cookie has a Max-Age of {days} days (> 1 year), increasing the exploitation window if stolen.",
                        remediation="Reduce the lifetime of session cookies to a few hours or days.",
                    ))
        except ValueError:
            pass

    # Scope too broad (4.6)
    cookie_domain = attr_map.get("domain", "")
    if cookie_domain and cookie_domain.startswith("."):
        issue_key = f"domain-scope:{name}"
        if issue_key not in seen:
            seen.add(issue_key)
            findings.append(FindingData(
                severity="medium",
                title=f"Cookie '{name}': scope too broad (Domain={cookie_domain})",
                description=f"The cookie is shared with all subdomains of {cookie_domain}. A compromised subdomain can access it.",
                remediation="Remove the Domain attribute or restrict it to the required subdomain.",
            ))

    # Secure
    issue_key = f"secure:{name}"
    if "secure" not in attrs and issue_key not in seen:
        seen.add(issue_key)
        findings.append(FindingData(
            severity="medium",
            title=f"Cookie '{name}' without Secure attribute (found on {path})",
            description=f"The cookie '{name}' may be transmitted over unencrypted HTTP connections.",
            remediation="Add the Secure attribute to all session cookies.",
        ))

    # HttpOnly
    issue_key = f"httponly:{name}"
    if "httponly" not in attrs and issue_key not in seen:
        seen.add(issue_key)
        findings.append(FindingData(
            severity="medium",
            title=f"Cookie '{name}' without HttpOnly attribute (found on {path})",
            description=f"The cookie '{name}' is accessible via JavaScript, which exposes it to XSS attacks.",
            remediation="Add the HttpOnly attribute to all session cookies.",
        ))

    # SameSite
    issue_key = f"samesite:{name}"
    samesite = attr_map.get("samesite", "")
    if not samesite and issue_key not in seen:
        seen.add(issue_key)
        findings.append(FindingData(
            severity="low",
            title=f"Cookie '{name}' without SameSite attribute (found on {path})",
            description=f"Without SameSite, the cookie '{name}' may be sent in cross-site requests (CSRF).",
            remediation="Add SameSite=Strict or SameSite=Lax as needed.",
        ))
    elif samesite == "none" and "secure" not in attrs and issue_key not in seen:
        seen.add(issue_key)
        findings.append(FindingData(
            severity="high",
            title=f"Cookie '{name}': SameSite=None without Secure (found on {path})",
            description="SameSite=None requires the Secure attribute, otherwise the cookie is rejected by modern browsers.",
            remediation="Add the Secure attribute or change to SameSite=Lax.",
        ))


# --- Phase 3: new checks ---


async def _check_http_methods(base_url: str, findings: list) -> None:
    """Checks whether dangerous HTTP methods are allowed (OPTIONS)."""
    try:
        async with httpx.AsyncClient(**_CLIENT_DEFAULTS) as client:
            resp = await client.options(base_url)
            allow = resp.headers.get("allow", "")
            if not allow:
                return
            methods = {m.strip().upper() for m in allow.split(",")}
            dangerous = methods & {"PUT", "DELETE", "TRACE", "CONNECT"}
            if dangerous:
                findings.append(FindingData(
                    severity="medium",
                    title=f"Dangerous HTTP methods allowed: {', '.join(sorted(dangerous))}",
                    description=f"The server allows {', '.join(sorted(dangerous))} via the Allow header.",
                    remediation="Disable unnecessary HTTP methods in the server configuration.",
                ))
    except httpx.HTTPError as exc:
        logger.debug("headers: HTTP methods check failed for %s: %s", base_url, exc)


async def _check_robots_sitemap(base_url: str, findings: list) -> None:
    """Analyzes robots.txt and checks sitemap.xml."""
    async with httpx.AsyncClient(**_CLIENT_DEFAULTS) as client:
        # robots.txt
        try:
            resp = await client.get(f"{base_url}/robots.txt")
            if resp.status_code == 200 and "disallow" in resp.text.lower():
                sensitive = [
                    "admin", "api", "backup", "config", "dashboard", "debug",
                    "internal", "private", "secret", "staging", "test", "deploy",
                ]
                exposed = []
                for line in resp.text.splitlines():
                    low = line.strip().lower()
                    if low.startswith("disallow:"):
                        path = low.split(":", 1)[1].strip()
                        for kw in sensitive:
                            if kw in path:
                                exposed.append(line.strip().split(":", 1)[1].strip())
                                break
                if exposed:
                    findings.append(FindingData(
                        severity="low",
                        title="robots.txt discloses sensitive paths",
                        description=f"Potentially sensitive paths listed in robots.txt: {', '.join(exposed[:5])}",
                        remediation="Check that these paths are not accessible without authentication.",
                    ))
        except httpx.HTTPError as exc:
            logger.debug("headers: robots.txt check failed for %s: %s", base_url, exc)

        # sitemap.xml
        try:
            resp = await client.get(f"{base_url}/sitemap.xml")
            if resp.status_code == 200 and ("<?xml" in resp.text[:200] or "<urlset" in resp.text[:500]):
                findings.append(FindingData(
                    severity="info",
                    title="sitemap.xml accessible",
                    description="The sitemap.xml file is publicly accessible and discloses the structure of the site.",
                    remediation="Check that the sitemap does not reference internal or protected pages.",
                ))
        except httpx.HTTPError as exc:
            logger.debug("headers: sitemap.xml check failed for %s: %s", base_url, exc)


async def _check_cache_control(base_url: str, findings: list) -> None:
    """Checks Cache-Control on sensitive pages (login, account...)."""
    sensitive_paths = ["/login", "/signin", "/account", "/admin", "/dashboard"]
    async with httpx.AsyncClient(**_CLIENT_DEFAULTS) as client:
        for path in sensitive_paths:
            try:
                resp = await client.get(f"{base_url}{path}")
                if resp.status_code != 200:
                    continue
                cc = resp.headers.get("cache-control", "").lower()
                if "no-store" not in cc and "no-cache" not in cc:
                    findings.append(FindingData(
                        severity="medium",
                        title=f"Cache-Control missing on sensitive page ({path})",
                        description=f"The page {path} does not contain 'no-store' in Cache-Control. It could be cached.",
                        remediation="Add Cache-Control: no-store, no-cache on authentication and sensitive pages.",
                    ))
                    return  # A single finding is enough
            except httpx.HTTPError as exc:
                logger.debug("headers: cache-control probe %s failed for %s: %s", path, base_url, exc)
                continue


async def _check_error_pages(base_url: str, findings: list) -> None:
    """Checks whether error pages expose stack traces."""
    try:
        async with httpx.AsyncClient(**_CLIENT_DEFAULTS) as client:
            resp = await client.get(f"{base_url}/a-nonexistent-page-security-test-73921")
            if resp.status_code < 400:
                return
            text = resp.text[:5000].lower()
            leak_patterns = [
                "traceback", "exception", "stack trace", "at java.", "at com.",
                "at org.", "at net.", "fatal error", "syntax error", "parse error",
                "sqlstate", "mysql_", "pg_query", "microsoft ole db",
            ]
            for pattern in leak_patterns:
                if pattern in text:
                    findings.append(FindingData(
                        severity="medium",
                        title="Verbose error page (technical information exposed)",
                        description=f"The error page contains '{pattern}', disclosing technical details useful to an attacker.",
                        remediation="Configure custom error pages without technical details in production.",
                    ))
                    return
    except httpx.HTTPError as exc:
        logger.debug("headers: error-page check failed for %s: %s", base_url, exc)
