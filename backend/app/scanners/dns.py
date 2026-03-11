import asyncio
import dns.resolver
import dns.asyncresolver

from app.scanners.base import BaseScanner, ScanResult, FindingData


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
        # Heuristique : tester les sélecteurs courants
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
