import asyncio
import json
import random
import string
from dataclasses import dataclass
from typing import cast

import dns.resolver
import dns.asyncresolver
import dns.rdtypes.ANY.MX
import dns.rdtypes.ANY.NS

from app.scanners.base import BaseScanner, ScanResult, FindingData
# Homograph analysis primitives shared with the validator (`schemas`).
# Centralized in `app.homograph` to avoid any divergence of the confusable
# character list between classification (here) and explanation (rejection).
from app.homograph import (
    CONFUSABLE_CHARS,
    alpha_scripts,
    is_legit_multiscript,
)


@dataclass
class MxProbeResult:
    """Outcome of a single SMTP probe against an MX host (checks 9.1 + 9.2).

    starttls:
        ``True``  -> the server answered EHLO and advertised STARTTLS.
        ``False`` -> the server answered EHLO but STARTTLS is absent.
        ``None``  -> indeterminate (unreachable, port 25 blocked, EHLO refused).
    cert_ok (only meaningful when ``starttls`` is True):
        ``True``  -> TLS handshake completed and the certificate verified
                     (trust chain, expiry, hostname == MX host).
        ``False`` -> certificate verification failed; ``cert_error`` holds why.
        ``None``  -> handshake failed for a non-certificate reason (timeout,
                     reset...) -> indeterminate, never a finding.
    """
    starttls: bool | None
    cert_ok: bool | None = None
    cert_error: str | None = None


class DnsScanner(BaseScanner):
    name = "dns"
    weight = 0.20

    async def scan(self, domain: str) -> ScanResult:
        findings: list[FindingData] = []
        resolver = dns.asyncresolver.Resolver()
        resolver.nameservers = ["8.8.8.8", "1.1.1.1"]

        await asyncio.gather(
            self._check_spf(domain, resolver, findings),
            self._check_dmarc(domain, resolver, findings),
            self._check_dkim(domain, resolver, findings),
            self._check_dnssec(domain, resolver, findings),
            self._check_mx(domain, resolver, findings),
            self._check_starttls_mx(domain, resolver, findings),
            self._check_caa(domain, resolver, findings),
            self._check_mta_sts(domain, resolver, findings),
            self._check_dane(domain, resolver, findings),
            self._check_spf_lookups(domain, resolver, findings),
            self._check_tls_rpt(domain, resolver, findings),
            self._check_bimi(domain, resolver, findings),
            self._check_axfr(domain, resolver, findings),
            self._check_wildcard(domain, resolver, findings),
            self._check_ns_redundancy(domain, resolver, findings),
            self._check_idn_homograph(domain, findings),
        )

        return ScanResult.from_findings(findings)

    async def _check_spf(self, domain: str, resolver: dns.asyncresolver.Resolver, findings: list) -> None:
        try:
            answers = await resolver.resolve(domain, "TXT")
            spf_records = [r.to_text() for r in answers if "v=spf1" in r.to_text()]
            if not spf_records:
                findings.append(FindingData(
                    severity="high",
                    title="SPF missing",
                    description=f"No SPF record found for {domain}.",
                    remediation="Add a TXT record: v=spf1 include:... ~all",
                ))
            elif len(spf_records) > 1:
                findings.append(FindingData(
                    severity="medium",
                    title="SPF duplicated",
                    description="Multiple SPF records detected. Only the first one is used.",
                    remediation="Merge into a single SPF record.",
                ))
            else:
                spf = spf_records[0]
                if "+all" in spf:
                    findings.append(FindingData(
                        severity="critical",
                        title="SPF too permissive (+all)",
                        description="The +all policy allows anyone to send emails on behalf of the domain.",
                        remediation="Replace +all with ~all or -all.",
                    ))
        except Exception:
            findings.append(FindingData(
                severity="high",
                title="SPF: unable to resolve",
                description=f"The DNS TXT query for {domain} failed.",
            ))

    async def _check_dmarc(self, domain: str, resolver: dns.asyncresolver.Resolver, findings: list) -> None:
        try:
            answers = await resolver.resolve(f"_dmarc.{domain}", "TXT")
            records = [r.to_text() for r in answers if "v=DMARC1" in r.to_text()]
            if not records:
                findings.append(FindingData(
                    severity="high",
                    title="DMARC missing",
                    description=f"No DMARC record found at _dmarc.{domain}.",
                    remediation='Add: v=DMARC1; p=quarantine; rua=mailto:dmarc@example.com',
                ))
            else:
                dmarc = records[0]
                if "p=none" in dmarc:
                    findings.append(FindingData(
                        severity="medium",
                        title="DMARC in monitoring mode (p=none)",
                        description="The none policy does not protect against spoofing, it only reports.",
                        remediation="Move to p=quarantine or p=reject once the reports have been analyzed.",
                    ))
        except dns.resolver.NXDOMAIN:
            findings.append(FindingData(
                severity="high",
                title="DMARC missing",
                description=f"No DMARC record found at _dmarc.{domain}.",
                remediation='Add: v=DMARC1; p=quarantine; rua=mailto:dmarc@example.com',
            ))
        except Exception:
            pass

    async def _check_dkim(self, domain: str, resolver: dns.asyncresolver.Resolver, findings: list) -> None:
        selectors = ["default", "google", "mail", "dkim", "k1", "selector1", "selector2"]
        found = False
        for selector in selectors:
            try:
                await resolver.resolve(f"{selector}._domainkey.{domain}", "TXT")
                found = True
                break
            except Exception:
                continue
        if not found:
            findings.append(FindingData(
                severity="medium",
                title="DKIM not detected",
                description="No common DKIM selector found. DKIM may be configured with a non-standard selector.",
                remediation="Check that DKIM is enabled with the email provider and publish the public key.",
            ))

    async def _check_dnssec(self, domain: str, resolver: dns.asyncresolver.Resolver, findings: list) -> None:
        try:
            answers = await resolver.resolve(domain, "DNSKEY")
            if not answers:
                raise Exception("no DNSKEY")
        except Exception:
            findings.append(FindingData(
                severity="low",
                title="DNSSEC not enabled",
                description="The domain does not use DNSSEC to sign its DNS records.",
                remediation="Enable DNSSEC with your registrar.",
            ))

    async def _check_mx(self, domain: str, resolver: dns.asyncresolver.Resolver, findings: list) -> None:
        try:
            await resolver.resolve(domain, "MX")
        except Exception:
            findings.append(FindingData(
                severity="info",
                title="No MX record",
                description="The domain does not appear to receive emails (no MX record).",
            ))

    async def _check_starttls_mx(self, domain: str, resolver: dns.asyncresolver.Resolver, findings: list) -> None:
        """Check STARTTLS support (9.1) and the MX TLS certificate (9.2).

        For every MX host we open a single SMTP connection on port 25, send EHLO
        and look for the STARTTLS capability in the advertised extensions. When
        STARTTLS is advertised, the same connection completes the TLS handshake
        and validates the certificate (trust chain, expiry, hostname against the
        MX host — not against the scanned domain).

        Critical caveat: outbound port 25 is very frequently blocked by cloud /
        CI / ISP networks (connection refused or timeout). When we cannot reach a
        host we treat the result as *indeterminate* — never as "STARTTLS missing"
        nor as an invalid certificate. Findings are only raised from a positive
        signal, so a blocked port can never degrade the score. Likewise, a TLS
        handshake that fails for a non-certificate reason is indeterminate for
        the certificate check.
        """
        try:
            mx_answers = await resolver.resolve(domain, "MX")
            # dnspython types the answer items as the base ``Rdata``; cast to the
            # concrete MX record type to expose the ``exchange`` attribute.
            mx_hosts = [
                str(cast(dns.rdtypes.ANY.MX.MX, r).exchange).rstrip(".")
                for r in mx_answers
            ]
        except Exception:
            return  # No MX → not applicable, no STARTTLS to check

        mx_hosts = [h for h in mx_hosts if h]
        if not mx_hosts:
            return

        loop = asyncio.get_event_loop()
        probed_hosts = mx_hosts[:3]

        async def _probe(mx_host: str) -> MxProbeResult | None:
            try:
                return await asyncio.wait_for(
                    loop.run_in_executor(None, _probe_starttls, mx_host),
                    timeout=15,
                )
            except Exception:
                return None  # timeout / executor error → indeterminate

        # Probe the (up to 3) hosts concurrently. Outbound port 25 is almost
        # always blocked in cloud/CI deployments, so serial probing would add up
        # to the sum of every per-host timeout; running them together caps the
        # worst case at a single timeout.
        results = await asyncio.gather(*(_probe(h) for h in probed_hosts))

        missing: list[str] = []
        reachable = 0
        invalid_certs: list[tuple[str, str]] = []
        valid_certs: list[str] = []
        for mx_host, result in zip(probed_hosts, results):
            if result is None or result.starttls is None:
                continue  # could not connect (port 25 blocked, refused...): skip
            reachable += 1
            if result.starttls is False:
                missing.append(mx_host)
            elif result.cert_ok is True:
                valid_certs.append(mx_host)
            elif result.cert_ok is False:
                invalid_certs.append(
                    (mx_host, result.cert_error or "certificate verification failed")
                )
            # cert_ok None with STARTTLS advertised: handshake failed for a
            # non-certificate reason → indeterminate for 9.2, nothing to report.

        if missing:
            findings.append(FindingData(
                severity="high",
                title="STARTTLS not offered by MX",
                description=(
                    "The following mail server(s) accept SMTP connections but do "
                    f"not advertise STARTTLS: {', '.join(missing)}. Emails to these "
                    "servers are delivered in cleartext and can be intercepted."
                ),
                remediation="Enable STARTTLS on the mail server(s) to encrypt SMTP transport.",
                raw_data=json.dumps({"mx_without_starttls": missing}),
            ))
        elif reachable == 0:
            # Single indeterminate finding covering both 9.1 and 9.2: no MX
            # reachable on port 25 means neither STARTTLS nor the certificate
            # could be verified — do not add a second noisy info finding.
            findings.append(FindingData(
                severity="info",
                title="STARTTLS: MX not testable",
                description=(
                    "Could not reach any MX server on port 25 (often blocked by "
                    "the network), so STARTTLS support and the MX TLS "
                    "certificate could not be verified."
                ),
            ))

        # 9.2 — MX TLS certificate (only from positive signals).
        if invalid_certs:
            reasons = "; ".join(f"{host}: {reason}" for host, reason in invalid_certs)
            findings.append(FindingData(
                severity="medium",
                title="Invalid TLS certificate on MX",
                description=(
                    "The following mail server(s) presented an invalid TLS "
                    f"certificate during the STARTTLS handshake: {reasons}. "
                    "Sending servers that verify certificates (MTA-STS, DANE) "
                    "may refuse to deliver email to them."
                ),
                remediation=(
                    "Deploy a CA-signed certificate matching the MX hostname "
                    "on the mail server(s), e.g. with Let's Encrypt."
                ),
                raw_data=json.dumps({"mx_invalid_cert": dict(invalid_certs)}),
            ))
        elif valid_certs:
            findings.append(FindingData(
                severity="info",
                title="MX TLS certificate valid",
                description=(
                    "The mail server(s) tested over STARTTLS presented a valid "
                    "TLS certificate (trusted chain, hostname, expiry): "
                    f"{', '.join(valid_certs)}."
                ),
                raw_data=json.dumps({"mx_valid_cert": valid_certs}),
            ))

    # --- Phase 1: new checks ---

    async def _check_caa(self, domain: str, resolver: dns.asyncresolver.Resolver, findings: list) -> None:
        try:
            await resolver.resolve(domain, "CAA")
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
            findings.append(FindingData(
                severity="medium",
                title="CAA missing",
                description="No CAA record. Any certificate authority can issue a certificate.",
                remediation='Add a CAA record: 0 issue "letsencrypt.org" (adapt to your CA).',
            ))
        except Exception:
            pass

    async def _check_mta_sts(self, domain: str, resolver: dns.asyncresolver.Resolver, findings: list) -> None:
        try:
            answers = await resolver.resolve(f"_mta-sts.{domain}", "TXT")
            records = [r.to_text() for r in answers if "v=STSv1" in r.to_text()]
            if not records:
                raise dns.resolver.NoAnswer()
        except Exception:
            findings.append(FindingData(
                severity="low",
                title="MTA-STS not configured",
                description="MTA-STS is not enabled. Emails in transit can be intercepted (STARTTLS downgrade).",
                remediation="Publish a TXT record _mta-sts and host the policy at https://mta-sts.{domain}.",
            ))

    async def _check_dane(self, domain: str, resolver: dns.asyncresolver.Resolver, findings: list) -> None:
        try:
            mx_answers = await resolver.resolve(domain, "MX")
            # dnspython types the answer items as the base ``Rdata``; cast to the
            # concrete MX record type to expose the ``exchange`` attribute.
            mx_hosts = [
                str(cast(dns.rdtypes.ANY.MX.MX, r).exchange).rstrip(".")
                for r in mx_answers
            ]
        except Exception:
            return  # No MX, no DANE to check

        for mx_host in mx_hosts[:3]:
            try:
                await resolver.resolve(f"_25._tcp.{mx_host}", "TLSA")
                return  # TLSA found, OK
            except Exception:
                continue

        findings.append(FindingData(
            severity="low",
            title="DANE/TLSA not configured",
            description="No TLSA record for the mail servers. DANE strengthens the security of email transport.",
            remediation="Publish TLSA records for _25._tcp.{mx_host} (requires DNSSEC).",
        ))

    async def _check_spf_lookups(self, domain: str, resolver: dns.asyncresolver.Resolver, findings: list) -> None:
        try:
            answers = await resolver.resolve(domain, "TXT")
            spf = next(
                (r.to_text().strip('"') for r in answers if "v=spf1" in r.to_text()),
                None,
            )
            if not spf:
                return

            count = 0
            for token in spf.split():
                t = token.lower().lstrip("+-~?")
                if t.startswith(("include:", "redirect=")):
                    count += 1
                elif t in ("a", "mx") or t.startswith(("a:", "a/", "mx:", "mx/", "ptr:", "ptr/", "exists:")):
                    count += 1

            if count > 10:
                findings.append(FindingData(
                    severity="medium",
                    title=f"SPF: too many DNS lookups ({count}/10 max)",
                    description="RFC 7208 limits to 10 DNS lookups. Beyond that, SPF is ignored by some servers.",
                    remediation="Reduce the includes or use SPF flattening.",
                ))
        except Exception:
            pass

    # --- Phase 3: additional DNS checks ---

    async def _check_tls_rpt(self, domain: str, resolver: dns.asyncresolver.Resolver, findings: list) -> None:
        try:
            answers = await resolver.resolve(f"_smtp._tls.{domain}", "TXT")
            records = [r.to_text() for r in answers if "v=TLSRPTv1" in r.to_text()]
            if not records:
                raise dns.resolver.NoAnswer()
        except Exception:
            findings.append(FindingData(
                severity="low",
                title="TLS-RPT not configured",
                description="No TLS-RPT record (_smtp._tls). Email TLS transport failures are not reported.",
                remediation="Add: _smtp._tls TXT \"v=TLSRPTv1; rua=mailto:tls-reports@your-domain\"",
            ))

    async def _check_bimi(self, domain: str, resolver: dns.asyncresolver.Resolver, findings: list) -> None:
        try:
            answers = await resolver.resolve(f"default._bimi.{domain}", "TXT")
            records = [r.to_text() for r in answers if "v=BIMI1" in r.to_text()]
            if not records:
                raise dns.resolver.NoAnswer()
        except Exception:
            findings.append(FindingData(
                severity="info",
                title="BIMI not configured",
                description="No BIMI record. The brand logo will not be displayed in compatible email clients.",
                remediation="Publish: default._bimi TXT \"v=BIMI1; l=<SVG logo URL>\" (requires DMARC p=quarantine or reject).",
            ))

    async def _check_axfr(self, domain: str, resolver: dns.asyncresolver.Resolver, findings: list) -> None:
        try:
            ns_answers = await resolver.resolve(domain, "NS")
        except Exception:
            return

        for ns in ns_answers:
            # Cast to the concrete NS record type to expose ``target``.
            ns_host = str(cast(dns.rdtypes.ANY.NS.NS, ns).target).rstrip(".")
            try:
                loop = asyncio.get_event_loop()
                result = await asyncio.wait_for(
                    loop.run_in_executor(None, _try_axfr, ns_host, domain),
                    timeout=10,
                )
                if result:
                    findings.append(FindingData(
                        severity="critical",
                        title=f"DNS zone transfer possible (AXFR) via {ns_host}",
                        description="The DNS server allows a full zone transfer. An attacker can obtain all of the domain's DNS records.",
                        remediation="Restrict zone transfers (AXFR) to authorized secondary DNS servers.",
                    ))
                    return
            except Exception:
                continue

    async def _check_wildcard(self, domain: str, resolver: dns.asyncresolver.Resolver, findings: list) -> None:
        random_sub = "".join(random.choices(string.ascii_lowercase, k=16))
        try:
            await resolver.resolve(f"{random_sub}.{domain}", "A")
            findings.append(FindingData(
                severity="medium",
                title="Wildcard DNS detected",
                description="A wildcard record (*.domain) is configured. All subdomains, even nonexistent ones, resolve to an address.",
                remediation="Remove the wildcard DNS unless necessary. It can mask misconfigured subdomains.",
            ))
        except Exception:
            pass

    async def _check_ns_redundancy(self, domain: str, resolver: dns.asyncresolver.Resolver, findings: list) -> None:
        try:
            ns_answers = await resolver.resolve(domain, "NS")
            ns_hosts = [
                str(cast(dns.rdtypes.ANY.NS.NS, r).target).rstrip(".")
                for r in ns_answers
            ]
        except Exception:
            return

        if len(ns_hosts) < 2:
            findings.append(FindingData(
                severity="medium",
                title=f"Insufficient NS ({len(ns_hosts)} server)",
                description="The domain has only a single DNS server. In case of an outage, the domain becomes unreachable.",
                remediation="Configure at least 2 DNS servers on distinct networks.",
            ))
            return

        # Check whether the NS are on distinct /24 networks
        ns_ips: list[str] = []
        for ns in ns_hosts[:4]:
            try:
                a = await resolver.resolve(ns, "A")
                ns_ips.append(str(a[0]))
            except Exception:
                continue

        if len(ns_ips) >= 2:
            networks = {ip.rsplit(".", 1)[0] for ip in ns_ips}
            if len(networks) < 2:
                findings.append(FindingData(
                    severity="medium",
                    title="NS servers on the same network",
                    description=f"The {len(ns_ips)} DNS servers are on the same /24 subnet. A network outage would affect them all.",
                    remediation="Spread the DNS servers across different physical networks.",
                ))


    async def _check_idn_homograph(self, domain: str, findings: list) -> None:
        """Passive detection of a homograph domain (IDN spoofing).

        Purely local analysis of the domain name: no network request (hence the
        absence of a `resolver` parameter, unlike the other DNS checks). The
        validator (`schemas.validate_domain`) converts the input to Punycode via
        `.encode("idna")`, so internationalized domains — including those a victim
        pastes in their visible Unicode form — arrive here encoded as `xn--`
        labels, ready to be decoded and analyzed.

        Known limitations:

        - The "confusable" detection relies on `CONFUSABLE_CHARS`, a partial
          allowlist (Cyrillic/Greek). Entire families of homoglyphs (Armenian,
          fullwidth, mathematical alphanumerics…) are not listed and fall back to
          "info". The most dangerous case (mix of Latin + another script, e.g.
          "pаypal") remains covered by the "mixed scripts" branch independently of
          this list.
        - Legitimate script combinations (Japanese Han+Kana, Korean Han+Hangul;
          cf. `app.homograph`) are whitelisted to avoid classifying perfectly
          valid IDNs as "high".
        - The Punycode conversion (validator + this check) relies on the stdlib
          `.encode("idna")` codec, which implements IDNA2003 and applies a silent
          mapping NOT conformant to modern browsers (UTS#46/IDNA2008) — e.g.
          "straße.de" → "strasse.de". For a tool comparing the appearance of a
          domain to its real form, the normalization may therefore differ from the
          one seen by the victim in their browser.
        """
        idn_labels: list[tuple[str, str]] = []  # (ASCII label, Unicode label)
        for label in domain.split("."):
            if not label.startswith("xn--"):
                continue
            try:
                unicode_label = label[4:].encode("ascii").decode("punycode")
            except Exception:
                continue
            idn_labels.append((label, unicode_label))

        if not idn_labels:
            return  # Pure ASCII domain: no homograph risk

        for ascii_label, unicode_label in idn_labels:
            scripts = alpha_scripts(unicode_label)
            alpha = [c for c in unicode_label if c.isalpha()]
            raw = json.dumps({
                "label": ascii_label,
                "unicode": unicode_label,
                "scripts": sorted(scripts),
            })

            if len(scripts) > 1 and not is_legit_multiscript(scripts):
                findings.append(FindingData(
                    severity="high",
                    title="Homograph domain: mixed scripts",
                    description=(
                        f"The label \"{unicode_label}\" ({ascii_label}) mixes several "
                        f"writing systems ({', '.join(sorted(scripts))}). This is the "
                        "signature of a homograph attack: characters that look "
                        "identical to Latin letters imitate a legitimate domain."
                    ),
                    remediation="Verify the authenticity of the domain and compare it with the Punycode form (xn--).",
                    raw_data=raw,
                ))
            elif alpha and "LATIN" not in scripts and all(c in CONFUSABLE_CHARS for c in alpha):
                findings.append(FindingData(
                    severity="medium",
                    title="Potential homograph domain (confusable characters)",
                    description=(
                        f"The label \"{unicode_label}\" ({ascii_label}) is entirely composed "
                        "of non-Latin characters that look identical to Latin letters. "
                        "It can visually spoof a legitimate ASCII domain."
                    ),
                    remediation="Verify the authenticity of the domain and compare it with the Punycode form (xn--).",
                    raw_data=raw,
                ))
            else:
                findings.append(FindingData(
                    severity="info",
                    title="Internationalized domain (IDN)",
                    description=(
                        f"The label \"{unicode_label}\" ({ascii_label}) uses non-ASCII "
                        "characters (IDN). No suspicious script mix detected."
                    ),
                    raw_data=raw,
                ))


def _probe_starttls(mx_host: str, timeout: float = 7.0) -> MxProbeResult:
    """Probe a single MX host for STARTTLS support and certificate validity
    (blocking, run in an executor).

    One SMTP connection feeds both checks: EHLO + capability sniffing for 9.1,
    then — only if STARTTLS is advertised — the TLS handshake on the same
    connection for 9.2. The certificate is validated with the system trust
    store (``ssl.create_default_context()``: chain + expiry) and the hostname
    is verified against the MX host (``smtplib`` passes the connection host as
    ``server_hostname``), NOT against the scanned domain.

    A connection failure (port 25 blocked, refused, timeout) yields
    ``starttls=None`` and must NOT be read as a missing-STARTTLS signal; a
    handshake that fails for a non-certificate reason yields ``cert_ok=None``.
    """
    import smtplib
    import ssl

    result = MxProbeResult(starttls=None)
    try:
        with smtplib.SMTP(mx_host, port=25, timeout=timeout) as smtp:
            code, _ = smtp.ehlo()
            if code < 200 or code >= 400:
                return result  # EHLO refused → cannot conclude
            if not smtp.has_extn("starttls"):
                result = MxProbeResult(starttls=False)
                return result
            result = MxProbeResult(starttls=True)
            try:
                smtp.starttls(context=ssl.create_default_context())
                result = MxProbeResult(starttls=True, cert_ok=True)
            except ssl.SSLCertVerificationError as exc:
                result = MxProbeResult(
                    starttls=True,
                    cert_ok=False,
                    cert_error=exc.verify_message or str(exc),
                )
            except Exception:
                pass  # handshake failed (timeout, reset...) → cert indeterminate
            return result
    except Exception:
        # Network / SMTP error → indeterminate, never a hit. ``result`` keeps
        # whatever was established before the failure (e.g. a cert verdict if
        # only the connection teardown blew up).
        return result


def _try_axfr(ns_host: str, domain: str) -> bool:
    """Attempt an AXFR zone transfer (blocking, to be run in an executor)."""
    import dns.query
    import dns.zone
    try:
        zone = dns.zone.from_xfr(dns.query.xfr(ns_host, domain, timeout=5))
        return len(zone.nodes) > 0
    except Exception:
        return False
