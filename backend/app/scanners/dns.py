import asyncio
import json
import random
import string

import dns.resolver
import dns.asyncresolver

from app.scanners.base import BaseScanner, ScanResult, FindingData
# Homograph analysis primitives shared with the validator (`schemas`).
# Centralized in `app.homograph` to avoid any divergence of the confusable
# character list between classification (here) and explanation (rejection).
from app.homograph import (
    CONFUSABLE_CHARS,
    alpha_scripts,
    is_legit_multiscript,
)


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
                    title="SPF manquant",
                    description=f"Aucun enregistrement SPF trouvé pour {domain}.",
                    remediation="Ajouter un enregistrement TXT : v=spf1 include:... ~all",
                ))
            elif len(spf_records) > 1:
                findings.append(FindingData(
                    severity="medium",
                    title="SPF dupliqué",
                    description="Plusieurs enregistrements SPF détectés. Seul le premier est utilisé.",
                    remediation="Fusionner en un seul enregistrement SPF.",
                ))
            else:
                spf = spf_records[0]
                if "+all" in spf:
                    findings.append(FindingData(
                        severity="critical",
                        title="SPF trop permissif (+all)",
                        description="La politique +all autorise n'importe qui à envoyer des emails au nom du domaine.",
                        remediation="Remplacer +all par ~all ou -all.",
                    ))
        except Exception:
            findings.append(FindingData(
                severity="high",
                title="SPF : impossible de résoudre",
                description=f"La requête DNS TXT pour {domain} a échoué.",
            ))

    async def _check_dmarc(self, domain: str, resolver: dns.asyncresolver.Resolver, findings: list) -> None:
        try:
            answers = await resolver.resolve(f"_dmarc.{domain}", "TXT")
            records = [r.to_text() for r in answers if "v=DMARC1" in r.to_text()]
            if not records:
                findings.append(FindingData(
                    severity="high",
                    title="DMARC manquant",
                    description=f"Aucun enregistrement DMARC trouvé sur _dmarc.{domain}.",
                    remediation='Ajouter : v=DMARC1; p=quarantine; rua=mailto:dmarc@example.com',
                ))
            else:
                dmarc = records[0]
                if "p=none" in dmarc:
                    findings.append(FindingData(
                        severity="medium",
                        title="DMARC en mode monitoring (p=none)",
                        description="La politique none ne protège pas contre le spoofing, elle ne fait que reporter.",
                        remediation="Passer à p=quarantine ou p=reject une fois les rapports analysés.",
                    ))
        except dns.resolver.NXDOMAIN:
            findings.append(FindingData(
                severity="high",
                title="DMARC manquant",
                description=f"Aucun enregistrement DMARC trouvé sur _dmarc.{domain}.",
                remediation='Ajouter : v=DMARC1; p=quarantine; rua=mailto:dmarc@example.com',
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
                title="DKIM non détecté",
                description="Aucun sélecteur DKIM courant trouvé. DKIM peut être configuré avec un sélecteur non standard.",
                remediation="Vérifier que DKIM est activé auprès du fournisseur email et publier la clé publique.",
            ))

    async def _check_dnssec(self, domain: str, resolver: dns.asyncresolver.Resolver, findings: list) -> None:
        try:
            answers = await resolver.resolve(domain, "DNSKEY")
            if not answers:
                raise Exception("no DNSKEY")
        except Exception:
            findings.append(FindingData(
                severity="low",
                title="DNSSEC non activé",
                description="Le domaine n'utilise pas DNSSEC pour signer ses enregistrements DNS.",
                remediation="Activer DNSSEC auprès de votre registrar.",
            ))

    async def _check_mx(self, domain: str, resolver: dns.asyncresolver.Resolver, findings: list) -> None:
        try:
            await resolver.resolve(domain, "MX")
        except Exception:
            findings.append(FindingData(
                severity="info",
                title="Pas d'enregistrement MX",
                description="Le domaine ne semble pas recevoir d'emails (absence de MX).",
            ))

    # --- Phase 1: new checks ---

    async def _check_caa(self, domain: str, resolver: dns.asyncresolver.Resolver, findings: list) -> None:
        try:
            await resolver.resolve(domain, "CAA")
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
            findings.append(FindingData(
                severity="medium",
                title="CAA manquant",
                description="Aucun enregistrement CAA. N'importe quelle autorité de certification peut émettre un certificat.",
                remediation='Ajouter un enregistrement CAA : 0 issue "letsencrypt.org" (adapter selon votre CA).',
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
                title="MTA-STS non configuré",
                description="MTA-STS n'est pas activé. Les emails en transit peuvent être interceptés (downgrade STARTTLS).",
                remediation="Publier un enregistrement TXT _mta-sts et héberger la policy sur https://mta-sts.{domain}.",
            ))

    async def _check_dane(self, domain: str, resolver: dns.asyncresolver.Resolver, findings: list) -> None:
        try:
            mx_answers = await resolver.resolve(domain, "MX")
            mx_hosts = [str(r.exchange).rstrip(".") for r in mx_answers]
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
            title="DANE/TLSA non configuré",
            description="Aucun enregistrement TLSA pour les serveurs mail. DANE renforce la sécurité du transport email.",
            remediation="Publier des enregistrements TLSA pour _25._tcp.{mx_host} (nécessite DNSSEC).",
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
                    title=f"SPF : trop de lookups DNS ({count}/10 max)",
                    description="Le RFC 7208 limite à 10 lookups DNS. Au-delà, le SPF est ignoré par certains serveurs.",
                    remediation="Réduire les includes ou utiliser le SPF flattening.",
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
                title="TLS-RPT non configuré",
                description="Aucun enregistrement TLS-RPT (_smtp._tls). Les échecs de transport TLS email ne sont pas reportés.",
                remediation="Ajouter : _smtp._tls TXT \"v=TLSRPTv1; rua=mailto:tls-reports@votre-domaine\"",
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
                title="BIMI non configuré",
                description="Aucun enregistrement BIMI. Le logo de marque ne s'affichera pas dans les clients email compatibles.",
                remediation="Publier : default._bimi TXT \"v=BIMI1; l=<URL du logo SVG>\" (nécessite DMARC p=quarantine ou reject).",
            ))

    async def _check_axfr(self, domain: str, resolver: dns.asyncresolver.Resolver, findings: list) -> None:
        try:
            ns_answers = await resolver.resolve(domain, "NS")
        except Exception:
            return

        for ns in ns_answers:
            ns_host = str(ns.target).rstrip(".")
            try:
                loop = asyncio.get_event_loop()
                result = await asyncio.wait_for(
                    loop.run_in_executor(None, _try_axfr, ns_host, domain),
                    timeout=10,
                )
                if result:
                    findings.append(FindingData(
                        severity="critical",
                        title=f"Transfert de zone DNS possible (AXFR) via {ns_host}",
                        description="Le serveur DNS autorise le transfert de zone complet. Un attaquant peut obtenir tous les enregistrements DNS du domaine.",
                        remediation="Restreindre les transferts de zone (AXFR) aux serveurs DNS secondaires autorisés.",
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
                title="Wildcard DNS détecté",
                description="Un enregistrement wildcard (*.domain) est configuré. Tous les sous-domaines, même inexistants, résolvent une adresse.",
                remediation="Supprimer le wildcard DNS sauf si nécessaire. Cela peut masquer des sous-domaines mal configurés.",
            ))
        except Exception:
            pass

    async def _check_ns_redundancy(self, domain: str, resolver: dns.asyncresolver.Resolver, findings: list) -> None:
        try:
            ns_answers = await resolver.resolve(domain, "NS")
            ns_hosts = [str(r.target).rstrip(".") for r in ns_answers]
        except Exception:
            return

        if len(ns_hosts) < 2:
            findings.append(FindingData(
                severity="medium",
                title=f"NS insuffisants ({len(ns_hosts)} serveur)",
                description="Le domaine n'a qu'un seul serveur DNS. En cas de panne, le domaine devient inaccessible.",
                remediation="Configurer au moins 2 serveurs DNS sur des réseaux distincts.",
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
                    title="Serveurs NS sur le même réseau",
                    description=f"Les {len(ns_ips)} serveurs DNS sont sur le même sous-réseau /24. Une panne réseau les affecterait tous.",
                    remediation="Répartir les serveurs DNS sur des réseaux physiques différents.",
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
                    title="Domaine homographe : scripts mélangés",
                    description=(
                        f"Le label « {unicode_label} » ({ascii_label}) mélange plusieurs "
                        f"systèmes d'écriture ({', '.join(sorted(scripts))}). C'est la "
                        "signature d'une attaque homographe : des caractères d'apparence "
                        "identique à des lettres latines imitent un domaine légitime."
                    ),
                    remediation="Vérifier l'authenticité du domaine et comparer avec la forme Punycode (xn--).",
                    raw_data=raw,
                ))
            elif alpha and "LATIN" not in scripts and all(c in CONFUSABLE_CHARS for c in alpha):
                findings.append(FindingData(
                    severity="medium",
                    title="Domaine homographe potentiel (caractères confusables)",
                    description=(
                        f"Le label « {unicode_label} » ({ascii_label}) est entièrement composé "
                        "de caractères non latins d'apparence identique à des lettres latines. "
                        "Il peut usurper visuellement un domaine ASCII légitime."
                    ),
                    remediation="Vérifier l'authenticité du domaine et comparer avec la forme Punycode (xn--).",
                    raw_data=raw,
                ))
            else:
                findings.append(FindingData(
                    severity="info",
                    title="Domaine internationalisé (IDN)",
                    description=(
                        f"Le label « {unicode_label} » ({ascii_label}) utilise des caractères "
                        "non ASCII (IDN). Aucun mélange de scripts suspect détecté."
                    ),
                    raw_data=raw,
                ))


def _try_axfr(ns_host: str, domain: str) -> bool:
    """Attempt an AXFR zone transfer (blocking, to be run in an executor)."""
    import dns.query
    import dns.zone
    try:
        zone = dns.zone.from_xfr(dns.query.xfr(ns_host, domain, timeout=5))
        return len(zone.nodes) > 0
    except Exception:
        return False
