# scanners/http_headers.py
import requests

from scanners.base import BaseScanner

headers = [
    {
        "name": "Cache-Control",
        "value": "no-store",
        "severity": "medium",
        "check_type": "contains",
        "description": "Prevents sensitive data from being cached by browsers or proxies."
    },
    {
        "name": "Clear-Site-Data",
        "value": "\"cache\",\"cookies\",\"storage\"",
        "severity": "low",
        "check_type": "present",
        "description": "Clears client-side storage to protect user data."
    },
    {
        "name": "Content-Security-Policy",
        "value": "default-src 'self'",
        "severity": "high",
        "check_type": "contains",
        "description": "Mitigates XSS, data injection, and clickjacking attacks."
    },
    {
        "name": "Cross-Origin-Embedder-Policy",
        "value": "require-corp",
        "severity": "high",
        "check_type": "exact",
        "description": "Prevents loading cross-origin resources without explicit permission."
    },
    {
        "name": "Cross-Origin-Opener-Policy",
        "value": "same-origin",
        "severity": "high",
        "check_type": "exact",
        "description": "Isolates browsing context to prevent cross-origin data leaks."
    },
    {
        "name": "Cross-Origin-Resource-Policy",
        "value": "same-origin",
        "severity": "high",
        "check_type": "exact",
        "description": "Prevents other origins from reading responses."
    },
    {
        "name": "Permissions-Policy",
        "value": "geolocation=(), microphone=(), camera=()",
        "severity": "medium",
        "check_type": "present",
        "description": "Restricts access to powerful browser features."
    },
    {
        "name": "Referrer-Policy",
        "value": "no-referrer",
        "severity": "medium",
        "check_type": "exact",
        "description": "Controls how much referrer information is sent with requests."
    },
    {
        "name": "Strict-Transport-Security",
        "value": "max-age=31536000",
        "severity": "high",
        "check_type": "contains",
        "description": "Enforces HTTPS and prevents SSL stripping attacks."
    },
    {
        "name": "X-Content-Type-Options",
        "value": "nosniff",
        "severity": "medium",
        "check_type": "exact",
        "description": "Prevents MIME type sniffing by browsers."
    },
    {
        "name": "X-DNS-Prefetch-Control",
        "value": "off",
        "severity": "low",
        "check_type": "exact",
        "description": "Controls DNS prefetching to improve privacy."
    },
    {
        "name": "X-Frame-Options",
        "allowed_values": ["deny", "sameorigin"],
        "severity": "medium",
        "check_type": "one_of",
        "description": "Prevents clickjacking by disallowing framing."
    },
    {
        "name": "X-Permitted-Cross-Domain-Policies",
        "value": "none",
        "severity": "low",
        "check_type": "exact",
        "description": "Restricts Adobe Flash and PDF cross-domain access."
    },
    {
        "name": "Origin-Agent-Cluster",
        "value": "?1",
        "severity": "low",
        "check_type": "exact",
        "description": "Improves isolation of origin-based data."
    }
]

# IF header missing:
#     report missing
# ELSE:
#     IF check_type == exact AND observed != expected:
#         report weak
#     IF check_type == contains AND expected not in observed:
#         report weak

class HTTPHeadersScanner(BaseScanner):
    
    name = "http_headers"

    def scan(self, target: str, timeout: int):
        findings = []
        try:
            response = requests.get(target, timeout=timeout)
            response_headers = {h.lower() for h in response.headers.keys()}
            response_headers_values = {h.lower() for h in response.headers.values()}
            
            for header in headers:
                header_name = header["name"].lower()

                if header_name not in response_headers:
                    findings.append({
                        "module_name": self.name,
                        "issue": f"{header['name']} header not found",
                        "evidence": f"{header['name']} header not found in response headers",
                        "severity_hint": header["severity"]
                    })
                else:
                    if(header["check_type"] == 'exact' AND header["value"] not in response_header_values):
                        missing_values = response_header_values - header["value"]
                        findings.append({
                        "module_name": self.name,
                        "issue": f"{header['name']} header is weak.",
                        "evidence": f"{header['name']} header has not found {missing_values} in response headers",
                        "severity_hint": header["severity"]
                        })
                    else:
                        findings.append({
                        "module_name": self.name,
                        "issue": f"{header['name']} header is weak but can be ignored.",
                        "evidence": f"{header['name']} header has not found {missing_values} in response headers",
                        "severity_hint": header["severity"]
                        })
                    
        except Exception:
            return []
        return findings

# for header in headers:
#     print(header["value"])

