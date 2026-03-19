# scanners/http_headers.py
import requests
from workers.scanner_modules.base import BaseScanner


def downgrade_severity(sev: str) -> str:
    return {
        "high": "medium",
        "medium": "low",
        "low": "info"
    }.get(sev, sev)

class HTTPHeadersScanner(BaseScanner):
    name = "http_headers"
    display_name = "HTTP Security Headers"
    tier = "passive"
    
    #missing dec in some headers
    HEADERS = [
        {
            "name": "Cache-Control",
            "value": "no-store",
            "severity": "medium",
            "check_type": "contains",
            "score_penalty": 10,
            "remediation": "Add 'Cache-Control: no-store' to prevent sensitive data being cached by browsers or proxies.",
        },
        {
            "name": "Clear-Site-Data",
            "severity": "low",
            "check_type": "present",
            "score_penalty": 5,
            "remediation": "Add 'Clear-Site-Data: *' on logout responses to clear client-side storage.",
        },
        {
            "name": "Content-Security-Policy",
            "value": "default-src 'self'",
            "severity": "high",
            "check_type": "contains",
            "score_penalty": 25,
            "remediation": "Add a Content-Security-Policy header. Start with 'default-src \\'self\\'' and expand as needed. See https://csp-evaluator.withgoogle.com for help.",
        },
        {
            "name": "Cross-Origin-Embedder-Policy",
            "value": "require-corp",
            "severity": "high",
            "check_type": "exact",
            "score_penalty": 15,
            "remediation": "Add 'Cross-Origin-Embedder-Policy: require-corp' to enable cross-origin isolation.",
        },
        {
            "name": "Cross-Origin-Opener-Policy",
            "value": "same-origin",
            "severity": "high",
            "check_type": "exact",
            "score_penalty": 15,
            "remediation": "Add 'Cross-Origin-Opener-Policy: same-origin' to prevent cross-origin window attacks.",
        },
        {
            "name": "Cross-Origin-Resource-Policy",
            "value": "same-origin",
            "severity": "high",
            "check_type": "exact",
            "score_penalty": 15,
            "remediation": "Add 'Cross-Origin-Resource-Policy: same-origin' to prevent cross-origin resource leaks.",
        },
        {
            "name": "Permissions-Policy",
            "severity": "medium",
            "check_type": "present",
            "score_penalty": 10,
            "remediation": "Add a Permissions-Policy header to control browser features. Example: 'Permissions-Policy: camera=(), microphone=(), geolocation=()'.",
        },
        {
            "name": "Referrer-Policy",
            "severity": "medium",
            "check_type": "one_of",
            "score_penalty": 10,
            "allowed_values": [
                "no-referrer",
                "no-referrer-when-downgrade",
                "origin",
                "origin-when-cross-origin",
                "same-origin",
                "strict-origin",
                "strict-origin-when-cross-origin",
                "unsafe-url",
            ],
            "remediation": "Add 'Referrer-Policy: no-referrer' or 'strict-origin-when-cross-origin' to control referrer leakage.",
        },
        {
            "name": "Strict-Transport-Security",
            "value": "max-age=31536000",
            "severity": "high",
            "check_type": "contains",
            "score_penalty": 25,
            "remediation": "Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains' to enforce HTTPS.",
        },
        {
            "name": "X-Content-Type-Options",
            "value": "nosniff",
            "severity": "medium",
            "check_type": "exact",
            "score_penalty": 10,
            "remediation": "Add 'X-Content-Type-Options: nosniff' to prevent MIME type sniffing attacks.",
        },
        {
            "name": "X-DNS-Prefetch-Control",
            "value": "off",
            "severity": "low",
            "check_type": "exact",
            "score_penalty": 5,
            "remediation": "Add 'X-DNS-Prefetch-Control: off' to prevent DNS prefetching leaking browsing behaviour.",
        },
        {
            "name": "X-Frame-Options",
            "severity": "medium",
            "check_type": "one_of",
            "score_penalty": 15,
            "allowed_values": ["deny", "sameorigin"],
            "remediation": "Add 'X-Frame-Options: DENY' to prevent your site being embedded in iframes (clickjacking protection).",
        },
        {
            "name": "X-Permitted-Cross-Domain-Policies",
            "value": "none",
            "severity": "low",
            "check_type": "exact",
            "score_penalty": 5,
            "remediation": "Add 'X-Permitted-Cross-Domain-Policies: none' to block Adobe Flash/PDF cross-domain requests.",
        },
        {
            "name": "Origin-Agent-Cluster",
            "value": "?1",
            "severity": "low",
            "check_type": "exact",
            "score_penalty": 5,
            "remediation": "Add 'Origin-Agent-Cluster: ?1' to enable origin-keyed agent clustering for better process isolation.",
        },
    ]
    
    def scan(self, target: str, timeout: int):
        findings = []
        try:
            response = requests.get(target, timeout=timeout)
            # requests.get(target,timeout=timeout,headers={"User-Agent": "VulnScanner/1.0"}) some servers block default requests
            # requests.get(target, timeout=timeout, allow_redirects=True) Handle redirects explicitly
            response_headers = {
                k.lower(): v.lower()
                for k, v in response.headers.items()
            }

            for header in self.HEADERS:
                name = header["name"].lower()
                check_type = header["check_type"]

                if name not in response_headers:
                    findings.append(self._finding(
                        issue=f"{header['name']} header missing",
                        evidence="Header not present in HTTP response",
                        severity=header["severity"],
                        remediation=header.get("remediation", f"Add the {header['name']} header to your server response."),
                        score_penalty=header.get("score_penalty", 0),
                    ))
                    continue

                observed = response_headers[name] #wo header ke name k corresponsding value jo exist karte hai

                if observed != header["value"].lower():
                    findings.append(self._finding(
                        issue=f"{header['name']} header misconfigured",
                        evidence=f"Expected '{header['value']}', got '{observed}'",
                        severity=downgrade_severity(header["severity"]),
                        remediation=header.get("remediation", f"Set {header['name']} to '{header['value']}'."),
                        score_penalty=header.get("score_penalty", 0),
                    ))

                elif check_type == "contains":
                    if header["value"].lower() not in observed:
                        findings.append(self._finding(
                            issue=f"{header['name']} header weak",
                            evidence=f"Expected to contain '{header['value']}', got '{observed}'",
                            severity=downgrade_severity(header["severity"]),
                            remediation=header.get("remediation", f"Set {header['name']} to '{header['value']}'."),
                            score_penalty=header.get("score_penalty", 0),
                        ))

                elif check_type == "one_of":
                    allowed = [v.lower() for v in header["allowed_values"]]
                    if observed not in allowed:
                        findings.append(self._finding(
                            issue=f"{header['name']} header weak",
                            evidence=f"Expected one of {allowed}, got '{observed}'",
                            severity=downgrade_severity(header["severity"]),
                            remediation=header.get("remediation", f"Set {header['name']} to one of: {', '.join(allowed)}."),
                            score_penalty=header.get("score_penalty", 0),
                        ))
        
        findings.extend(self._check_dangerous_headers(response_headers))
        findings.extend(self._check_hsts(response_headers))
        findings.extend(self._check_csp(response_headers))

        except requests.RequestException as e:
            return [self._finding(
                issue="HTTP request failed",
                evidence=str(e),
                severity="medium",
                remediation="Check that the target URL is reachable and returns a valid HTTP response.",
                score_penalty=20,
            )]

        return findings
    
    def _check_dangerous_headers(self, response_headers: dict) -> list:
    """
    Check for headers that should NOT be present —
    they leak server information and help attackers fingerprint the stack.
    """
    findings = []

    dangerous = [
        {
            "name": "server",
            "issue": "Server header exposes software info",
            "remediation": "Configure your server to remove or genericise the Server header. "
                           "Nginx: 'server_tokens off;' Apache: 'ServerTokens Prod'",
            "score_penalty": 10,
        },
        {
            "name": "x-powered-by",
            "issue": "X-Powered-By header exposes technology stack",
            "remediation": "Remove the X-Powered-By header. "
                           "Express.js: 'app.disable(\"x-powered-by\")' "
                           "PHP: 'expose_php = Off' in php.ini",
            "score_penalty": 10,
        },
        {
            "name": "x-aspnet-version",
            "issue": "X-AspNet-Version header exposes .NET version",
            "remediation": "Remove X-AspNet-Version in Web.config: "
                           "<httpRuntime enableVersionHeader=\"false\" />",
            "score_penalty": 10,
        },
        {
            "name": "x-aspnetmvc-version",
            "issue": "X-AspNetMvc-Version header exposes MVC version",
            "remediation": "Add 'MvcHandler.DisableMvcResponseHeader = true;' in Global.asax",
            "score_penalty": 10,
        },
    ]

    for header in dangerous:
        if header["name"] in response_headers:
            findings.append(self._finding(
                issue=header["issue"],
                evidence=f"Header present with value: '{response_headers[header['name']]}'",
                severity="medium",
                remediation=header["remediation"],
                score_penalty=header["score_penalty"],
            ))

    return findings


    def _check_hsts(self, response_headers: dict) -> list:
        """
        Deep validation of Strict-Transport-Security beyond just presence.
        Checks max-age value, includeSubDomains, and preload directives.
        """
        findings = []

        hsts = response_headers.get("strict-transport-security")
        if not hsts:
            return findings  # Already caught by the main HEADERS check

        directives = [d.strip() for d in hsts.split(";")]

        # Check max-age value
        max_age = None
        for d in directives:
            if d.startswith("max-age="):
                try:
                    max_age = int(d.split("=")[1])
                except ValueError:
                    findings.append(self._finding(
                        issue="HSTS max-age is not a valid number",
                        evidence=f"Parsed value: '{d}'",
                        severity="high",
                        remediation="Set a valid max-age value e.g. 'Strict-Transport-Security: max-age=31536000'",
                        score_penalty=20,
                    ))

        if max_age is not None and max_age < 31536000:
            findings.append(self._finding(
                issue="HSTS max-age is too short",
                evidence=f"max-age is {max_age} seconds ({max_age // 86400} days) — minimum recommended is 31536000 (1 year)",
                severity="medium",
                remediation="Set max-age to at least 31536000 (1 year): 'Strict-Transport-Security: max-age=31536000'",
                score_penalty=15,
            ))

        # Check includeSubDomains
        if "includesubdomains" not in [d.lower() for d in directives]:
            findings.append(self._finding(
                issue="HSTS missing includeSubDomains directive",
                evidence=f"Current value: '{hsts}'",
                severity="low",
                remediation="Add 'includeSubDomains' to your HSTS header: 'Strict-Transport-Security: max-age=31536000; includeSubDomains'",
                score_penalty=5,
            ))

        # Check preload
        if "preload" not in [d.lower() for d in directives]:
            findings.append(self._finding(
                issue="HSTS missing preload directive",
                evidence=f"Current value: '{hsts}'",
                severity="low",
                remediation="Add 'preload' and submit your domain to https://hstspreload.org for maximum HSTS protection.",
                score_penalty=5,
            ))

        return findings


    def _check_csp(self, response_headers: dict) -> list:
        """
        Basic CSP sanity checks — flags directives that make CSP
        effectively useless even if the header is present.
        """
        findings = []

        csp = response_headers.get("content-security-policy")
        if not csp:
            return findings  # Already caught by the main HEADERS check

        dangerous_values = [
            {
                "value": "unsafe-inline",
                "issue": "CSP allows unsafe-inline scripts",
                "evidence": f"CSP contains 'unsafe-inline': '{csp}'",
                "remediation": "Remove 'unsafe-inline' from CSP and use nonces or hashes instead. "
                            "See https://csp-evaluator.withgoogle.com",
                "score_penalty": 20,
            },
            {
                "value": "unsafe-eval",
                "issue": "CSP allows unsafe-eval",
                "evidence": f"CSP contains 'unsafe-eval': '{csp}'",
                "remediation": "Remove 'unsafe-eval' from CSP. Refactor code that uses eval(), "
                            "setTimeout(string), or similar patterns.",
                "score_penalty": 20,
            },
            {
                "value": "default-src *",
                "issue": "CSP uses wildcard default-src",
                "evidence": f"CSP contains 'default-src *': '{csp}'",
                "remediation": "Replace 'default-src *' with explicit trusted sources. "
                            "A wildcard CSP provides no protection.",
                "score_penalty": 25,
            },
        ]

        for item in dangerous_values:
            if item["value"] in csp.lower():
                findings.append(self._finding(
                    issue=item["issue"],
                    evidence=item["evidence"],
                    severity="high",
                    remediation=item["remediation"],
                    score_penalty=item["score_penalty"],
                ))

        return findings
