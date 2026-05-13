import dns.resolver
import dns.dnssec
import dns.name
import dns.query
import dns.zone
from urllib.parse import urlparse

from .base import BaseScanner, Finding


class DNSScanner(BaseScanner):
    name = "dns"
    display_name = "DNS Configuration"
    tier = "passive"
    
    def scan(self, target: str, timeout: int = 10) -> list[Finding]:
        findings = []

        # Extract hostname from URL
        parsed = urlparse(target)
        domain = parsed.hostname

        if not domain:
            return [self._finding(
                issue="Invalid target",
                evidence=f"Could not extract domain from: {target}",
                severity="medium",
                remediation="Ensure the URL is well-formed, e.g. https://example.com",
            )]

        # Run all checks
        findings.extend(self._check_spf(domain))
        findings.extend(self._check_dmarc(domain))
        findings.extend(self._check_dnssec(domain))
        findings.extend(self._check_caa(domain))
        findings.extend(self._check_mx(domain))

        return findings
    
    def _check_spf(self, domain: str) -> list[Finding]:
        """
        Check if the domain has a valid SPF record and whether
        it is strict enough to prevent email spoofing.
        """
        findings = []

        try:
            answers = dns.resolver.resolve(domain, "TXT")
            spf_records = [
                r.to_text().strip('"')
                for r in answers
                if "v=spf1" in r.to_text()
            ]

            if not spf_records:
                return [self._finding(
                    issue="SPF record missing",
                    evidence=f"No SPF TXT record found for {domain}",
                    severity="high",
                    remediation=(
                        "Add an SPF record to your DNS. Example: "
                        "'v=spf1 include:_spf.google.com ~all' "
                        "Without SPF, anyone can send spoofed emails from your domain."
                    ),
                    score_penalty=25,
                )]

            spf = spf_records[0]

            findings.append(self._finding(
                issue="SPF record found",
                evidence=spf,
                severity="info",
            ))

            # Check strictness of the SPF policy
            if "-all" in spf:
                findings.append(self._finding(
                    issue="SPF policy is strict",
                    evidence=f"'-all' directive rejects unauthorized senders: {spf}",
                    severity="info",
                ))
            elif "~all" in spf:
                findings.append(self._finding(
                    issue="SPF policy is weak",
                    evidence=f"'~all' only soft-fails unauthorized senders — they may still be delivered: {spf}",
                    severity="medium",
                    remediation="Change '~all' to '-all' to reject unauthorized senders outright.",
                    score_penalty=10,
                ))
            elif "+all" in spf:
                findings.append(self._finding(
                    issue="SPF policy allows all senders",
                    evidence=f"'+all' means anyone can send email as your domain: {spf}",
                    severity="high",
                    remediation="Replace '+all' with '-all' immediately. '+all' makes SPF completely useless.",
                    score_penalty=30,
                ))

        except dns.resolver.NXDOMAIN:
            findings.append(self._finding(
                issue="Domain does not exist",
                evidence=f"NXDOMAIN response for {domain}",
                severity="high",
                remediation="Verify the domain name is correct.",
                score_penalty=50,
            ))
        except dns.resolver.NoAnswer:
            findings.append(self._finding(
                issue="SPF record missing",
                evidence=f"No TXT records found for {domain}",
                severity="high",
                remediation="Add an SPF TXT record to your DNS configuration.",
                score_penalty=25,
            ))
        except Exception as e:
            findings.append(self._finding(
                issue="SPF check error",
                evidence=str(e),
                severity="low",
            ))

        return findings


    def _check_dmarc(self, domain: str) -> list[Finding]:
        """
        Check if the domain has a DMARC record and whether
        the policy is strong enough.
        """
        findings = []

        try:
            # DMARC record always lives at _dmarc.domain
            dmarc_domain = f"_dmarc.{domain}"
            answers = dns.resolver.resolve(dmarc_domain, "TXT")

            dmarc_records = [
                r.to_text().strip('"')
                for r in answers
                if "v=DMARC1" in r.to_text()
            ]

            if not dmarc_records:
                return [self._finding(
                    issue="DMARC record missing",
                    evidence=f"No DMARC record found at {dmarc_domain}",
                    severity="high",
                    remediation=(
                        "Add a DMARC TXT record at _dmarc.yourdomain.com. Example: "
                        "'v=DMARC1; p=reject; rua=mailto:reports@yourdomain.com' "
                        "Without DMARC, SPF failures may still be delivered."
                    ),
                    score_penalty=25,
                )]

            dmarc = dmarc_records[0]

            findings.append(self._finding(
                issue="DMARC record found",
                evidence=dmarc,
                severity="info",
            ))

            # Check policy strength
            if "p=reject" in dmarc:
                findings.append(self._finding(
                    issue="DMARC policy is strict",
                    evidence=f"p=reject blocks unauthorized emails outright: {dmarc}",
                    severity="info",
                ))
            elif "p=quarantine" in dmarc:
                findings.append(self._finding(
                    issue="DMARC policy is moderate",
                    evidence=f"p=quarantine sends unauthorized emails to spam: {dmarc}",
                    severity="low",
                    remediation="Consider upgrading to p=reject for maximum protection.",
                    score_penalty=5,
                ))
            elif "p=none" in dmarc:
                findings.append(self._finding(
                    issue="DMARC policy is too weak",
                    evidence=f"p=none only monitors — unauthorized emails are still delivered: {dmarc}",
                    severity="medium",
                    remediation=(
                        "Change p=none to p=quarantine or p=reject. "
                        "p=none provides no protection — it only sends reports."
                    ),
                    score_penalty=15,
                ))

        except dns.resolver.NXDOMAIN:
            findings.append(self._finding(
                issue="DMARC record missing",
                evidence=f"No DMARC record found at _dmarc.{domain}",
                severity="high",
                remediation=(
                    "Add a DMARC TXT record at _dmarc.yourdomain.com. "
                    "Without DMARC, email spoofing from your domain is trivially easy."
                ),
                score_penalty=25,
            ))
        except dns.resolver.NoAnswer:
            findings.append(self._finding(
                issue="DMARC record missing",
                evidence=f"No TXT records at _dmarc.{domain}",
                severity="high",
                remediation="Add a DMARC record to your DNS configuration.",
                score_penalty=25,
            ))
        except Exception as e:
            findings.append(self._finding(
                issue="DMARC check error",
                evidence=str(e),
                severity="low",
            ))

        return findings


    def _check_dnssec(self, domain: str) -> list[Finding]:
        """
        Check if DNSSEC is enabled for the domain by looking
        for DNSKEY records.
        """
        findings = []

        try:
            dns.resolver.resolve(domain, "DNSKEY")
            findings.append(self._finding(
                issue="DNSSEC enabled",
                evidence=f"DNSKEY record found for {domain}",
                severity="info",
            ))

        except dns.resolver.NoAnswer:
            findings.append(self._finding(
                issue="DNSSEC not enabled",
                evidence=f"No DNSKEY record found for {domain}",
                severity="medium",
                remediation=(
                    "Enable DNSSEC through your domain registrar or DNS provider. "
                    "DNSSEC prevents DNS spoofing and man-in-the-middle attacks on DNS responses."
                ),
                score_penalty=15,
            ))
        except dns.resolver.NXDOMAIN:
            findings.append(self._finding(
                issue="Domain does not exist",
                evidence=f"NXDOMAIN for {domain}",
                severity="high",
                remediation="Verify the domain name is correct.",
                score_penalty=50,
            ))
        except Exception as e:
            findings.append(self._finding(
                issue="DNSSEC check error",
                evidence=str(e),
                severity="low",
            ))

        return findings


    def _check_caa(self, domain: str) -> list[Finding]:
        """
        Check if the domain has a CAA record restricting which
        certificate authorities can issue SSL certificates.
        """
        findings = []

        try:
            answers = dns.resolver.resolve(domain, "CAA")
            caa_records = [r.to_text() for r in answers]

            findings.append(self._finding(
                issue="CAA record found",
                evidence=f"Authorized CAs: {', '.join(caa_records)}",
                severity="info",
            ))

        except dns.resolver.NoAnswer:
            findings.append(self._finding(
                issue="CAA record missing",
                evidence=f"No CAA record found for {domain}",
                severity="low",
                remediation=(
                    "Add a CAA record to restrict which CAs can issue certificates for your domain. "
                    "Example: '0 issue \"letsencrypt.org\"' "
                    "Without CAA, any CA in the world can issue a certificate for your domain."
                ),
                score_penalty=5,
            ))
        except dns.resolver.NXDOMAIN:
            findings.append(self._finding(
                issue="Domain does not exist",
                evidence=f"NXDOMAIN for {domain}",
                severity="high",
                score_penalty=50,
                remediation="Verify the domain name is correct.",
            ))
        except Exception as e:
            findings.append(self._finding(
                issue="CAA check error",
                evidence=str(e),
                severity="low",
            ))

        return findings


    def _check_mx(self, domain: str) -> list[Finding]:
        """
        Check if the domain has MX records configured.
        Purely informational — missing MX just means no email.
        """
        findings = []

        try:
            answers = dns.resolver.resolve(domain, "MX")
            mx_records = sorted(
                [(r.preference, str(r.exchange)) for r in answers],
                key=lambda x: x[0]
            )

            findings.append(self._finding(
                issue="MX records found",
                evidence=f"Mail servers: {', '.join(f'{pref} {ex}' for pref, ex in mx_records)}",
                severity="info",
            ))

        except dns.resolver.NoAnswer:
            findings.append(self._finding(
                issue="No MX records found",
                evidence=f"Domain {domain} has no MX records — email is not configured",
                severity="info",
                remediation="If this domain sends or receives email, add MX records via your DNS provider.",
            ))
        except dns.resolver.NXDOMAIN:
            findings.append(self._finding(
                issue="Domain does not exist",
                evidence=f"NXDOMAIN for {domain}",
                severity="high",
                remediation="Verify the domain name is correct.",
                score_penalty=50,
            ))
        except Exception as e:
            findings.append(self._finding(
                issue="MX check error",
                evidence=str(e),
                severity="low",
            ))

        return findings