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