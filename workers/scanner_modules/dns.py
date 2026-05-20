import dns.resolver
import dns.dnssec
import dns.name
import dns.query
import re
import dns.zone
from urllib.parse import urlparse

from .base import BaseScanner, Finding


class DNSScanner(BaseScanner):
    name = "dns"
    display_name = "DNS Configuration"
    tier = "passive"

    MANAGED_PLATFORM_SUFFIXES = (
        ".up.railway.app",
        ".railway.app",
        ".vercel.app",
        ".netlify.app",
        ".fly.dev",
        ".render.com",
    )

    def _dns_error_finding(
        self,
        *,
        issue: str,
        domain: str,
        record_type: str,
        lookup_name: str,
        error: Exception,
    ) -> Finding:
        error_type = type(error).__name__
        return self._finding(
            issue=issue,
            evidence=(
                f"{record_type} lookup for {lookup_name} failed while scanning {domain}. "
                f"Resolver error: {error_type}: {error}"
            ),
            severity="low",
            remediation=(
                f"Investigate DNS resolution for {lookup_name} ({record_type}). "
                "Check authoritative nameservers, resolver reachability, firewall rules, "
                "and retry the scan from a network with reliable DNS access."
            ),
        )
    
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

        if self._is_managed_platform_domain(domain):
            return [self._finding(
                issue="Managed platform domain detected",
                evidence=f"{domain} is a provider-owned deployment subdomain.",
                severity="info",
                remediation=(
                    "DNS ownership checks such as SPF, DMARC, DNSSEC, and CAA are only actionable "
                    "on a domain you control. Attach a custom domain and scan that domain for DNS hardening."
                ),
            )]

        # Run all checks
        findings.extend(self._check_spf(domain))
        findings.extend(self._check_dmarc(domain))
        findings.extend(self._check_dnssec(domain))
        findings.extend(self._check_caa(domain))
        findings.extend(self._check_mx(domain))

        return findings

    def _is_managed_platform_domain(self, domain: str) -> bool:
        normalized = domain.lower().rstrip(".")
        return any(normalized.endswith(suffix) for suffix in self.MANAGED_PLATFORM_SUFFIXES)
    
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
                evidence=(
                    f"TXT lookup for {domain} failed during SPF inspection. "
                    f"Resolver error: {type(e).__name__}: {e}"
                ),
                severity="low",
                remediation=(
                    "Investigate TXT record resolution for the root domain. "
                    "If DNS is reachable, add or correct the SPF TXT record."
                ),
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
            policy_match = re.search(r'(?<![a-z])p=(\w+)', dmarc)
            policy = policy_match.group(1).lower() if policy_match else None

            if policy == "reject":
                findings.append(self._finding(
                    issue="DMARC policy is strict",
                    evidence=f"p=reject blocks unauthorized emails outright: {dmarc}",
                    severity="info",
                ))
            elif policy == "quarantine":
                findings.append(self._finding(
                    issue="DMARC policy is moderate",
                    evidence=f"p=quarantine sends unauthorized emails to spam: {dmarc}",
                    severity="low",
                    remediation="Consider upgrading to p=reject for maximum protection.",
                    score_penalty=5,
                ))
            elif policy == "none":
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
            else:
                findings.append(self._finding(
                    issue="DMARC policy unrecognised",
                    evidence=f"Could not determine policy from: {dmarc}",
                    severity="low",
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
            findings.append(self._dns_error_finding(
                issue="DMARC check error",
                domain=domain,
                record_type="TXT",
                lookup_name=f"_dmarc.{domain}",
                error=e,
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
            findings.append(self._dns_error_finding(
                issue="DNSSEC check error",
                domain=domain,
                record_type="DNSKEY",
                lookup_name=domain,
                error=e,
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
            findings.append(self._dns_error_finding(
                issue="CAA check error",
                domain=domain,
                record_type="CAA",
                lookup_name=domain,
                error=e,
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
            findings.append(self._dns_error_finding(
                issue="MX check error",
                domain=domain,
                record_type="MX",
                lookup_name=domain,
                error=e,
            ))

        return findings
