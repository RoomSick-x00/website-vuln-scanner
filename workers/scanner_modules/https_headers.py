# scanners/http_headers.py
import requests
from scanners.base import BaseScanner

headers = [
    {
        "name": "Cache-Control",
        "value": "no-store",
        "severity": "medium",
        "check_type": "contains",
        "description": "Prevents sensitive data from being cached."
    },
    {
        "name": "Clear-Site-Data",
        "severity": "low",
        "check_type": "present",
        "description": "Clears client-side storage."
    },
    {
        "name": "Content-Security-Policy",
        "value": "default-src 'self'",
        "severity": "high",
        "check_type": "contains",
        "description": "Mitigates XSS and injection attacks."
    },
    {
        "name": "Cross-Origin-Embedder-Policy",
        "value": "require-corp",
        "severity": "high",
        "check_type": "exact"
    },
    {
        "name": "Cross-Origin-Opener-Policy",
        "value": "same-origin",
        "severity": "high",
        "check_type": "exact"
    },
    {
        "name": "Cross-Origin-Resource-Policy",
        "value": "same-origin",
        "severity": "high",
        "check_type": "exact"
    },
    {
        "name": "Permissions-Policy",
        "severity": "medium",
        "check_type": "present"
    },
    {
        "name": "Referrer-Policy",
        "value": "no-referrer",
        "severity": "medium",
        "check_type": "exact"
    },
    {
        "name": "Strict-Transport-Security",
        "value": "max-age=31536000",
        "severity": "high",
        "check_type": "contains"
    },
    {
        "name": "X-Content-Type-Options",
        "value": "nosniff",
        "severity": "medium",
        "check_type": "exact"
    },
    {
        "name": "X-DNS-Prefetch-Control",
        "value": "off",
        "severity": "low",
        "check_type": "exact"
    },
    {
        "name": "X-Frame-Options",
        "allowed_values": ["deny", "sameorigin"],
        "severity": "medium",
        "check_type": "one_of"
    },
    {
        "name": "X-Permitted-Cross-Domain-Policies",
        "value": "none",
        "severity": "low",
        "check_type": "exact"
    },
    {
        "name": "Origin-Agent-Cluster",
        "value": "?1",
        "severity": "low",
        "check_type": "exact"
    }
]

def downgrade_severity(sev: str) -> str:
    return {
        "high": "medium",
        "medium": "low",
        "low": "info"
    }.get(sev, sev)

class HTTPHeadersScanner(BaseScanner):
    name = "http_headers"

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

            for header in headers:
                name = header["name"].lower()
                check_type = header["check_type"]

                if name not in response_headers:
                    findings.append({
                        "module_name": self.name,
                        "issue": f"{header['name']} header missing",
                        "evidence": "Header not present in HTTP response",
                        "severity_hint": header["severity"]
                    })
                    continue

                observed = response_headers[name] #wo header ke name k corresponsding value jo exist karte hai

                if check_type == "exact":
                    if observed != header["value"].lower():
                        findings.append({
                            "module_name": self.name,
                            "issue": f"{header['name']} header misconfigured",
                            "evidence": f"Expected '{header['value']}', got '{observed}'",
                            "severity_hint": downgrade_severity(header["severity"])
                        })

                elif check_type == "contains":
                    if header["value"].lower() not in observed:
                        findings.append({
                            "module_name": self.name,
                            "issue": f"{header['name']} header weak",
                            "evidence": f"Expected to contain '{header['value']}', got '{observed}'",
                            "severity_hint": downgrade_severity(header["severity"])
                        })

                elif check_type == "one_of":
                    allowed = [v.lower() for v in header["allowed_values"]]
                    if observed not in allowed:
                        findings.append({
                            "module_name": self.name,
                            "issue": f"{header['name']} header weak",
                            "evidence": f"Expected one of {allowed}, got '{observed}'",
                            "severity_hint": downgrade_severity(header["severity"])
                        })

        except requests.RequestException:
            return []

        return findings
