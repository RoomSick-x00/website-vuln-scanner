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
                        "issue": f"{header['name']} header not found",
                        "evidence": f"{header['name']} header not found in response headers",
                        "severity_hint": header["severity"]
                    })
                    continue
    
                observed = response_headers[name] #wo headers k name jo missing nhi hai
                if check_type == "exact":       
                    if observed != header["value"].lower():
                        findings.append({
                        "module_name": self.name,
                        "issue": f"{header['name']} header is weak.",
                        "evidence": f"{header['name']} header has not found some values with exact int in response headers",
                        "severity_hint": header["severity"]
                        })
                        pass
                        
                elif check_type == "contains": 
                    if header["value"].lower() not in observed:
                        findings.append({
                        "module_name": self.name,
                        "issue": f"{header['name']} header is weak but needs some minor changes.",
                        "evidence": f"{header['name']} header has not found in response headers",
                        "severity_hint": header["severity"]
                        })
                        pass
                    
                elif check_type == "present":
                    findings.append({
                        "module_name": self.name,
                        "issue": f"{header['name']} header is weak but can be ignored.",
                        "evidence": f"{header['name']} header has not found in response headers",
                        "severity_hint": header["severity"]
                        })
                    pass
                    
        except Exception:
            return []
        return findings

# for header in headers:
#     print(header["value"])

