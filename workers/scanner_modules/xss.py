import requests
from bs4 import BeautifulSoup
from urllib.parse import urlparse, urlencode, parse_qs, urljoin

from .base import BaseScanner, Finding

class XSSScanner(BaseScanner):
    name = "xss"
    display_name = "XSS (Cross-Site Scripting)"
    tier = "intrusive"

    PROBE = "xsstest<b>probe123</b>"
    PROBE_MARKER = "xsstest<b>probe123</b>"
    
    def scan(self, target: str, timeout: int = 10) -> list[Finding]:
        findings = []

        try:
            response = requests.get(
                target,
                timeout=timeout,
                headers={"User-Agent": "Mozilla/5.0 (compatible; VulnScanner/1.0)"},
                allow_redirects=True,
            )
        except requests.RequestException as e:
            return [self._finding(
                issue="XSS scan failed — could not reach target",
                evidence=str(e),
                severity="medium",
                remediation="Check that the target URL is reachable.",
                score_penalty=0,
            )]

        if self._requires_login(response):
            return [self._finding(
                issue="XSS scan skipped — page requires authentication",
                evidence="Login form detected or access denied",
                severity="info",
                remediation="XSS scanning of authenticated pages requires manual testing.",
                score_penalty=0,
            )]

        soup = BeautifulSoup(response.text, "html.parser")

        findings.extend(self._check_url_parameters(target, response, timeout))
        findings.extend(self._check_forms(target, soup, timeout))

        if not findings:
            findings.append(self._finding(
                issue="No XSS vulnerabilities detected",
                evidence="No reflected input found in URL parameters or forms",
                severity="info",
            ))

        return findings