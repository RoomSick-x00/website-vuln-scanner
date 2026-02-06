# scanners/http_headers.py

from scanners.base import BaseScanner

class HTTPHeadersScanner(BaseScanner):
    name = "http_headers"

    def scan(self, target: str, timeout: int):
        findings = []
        try:
            response = requests.get(target, timeout=timeout)
            headers_list = list(response.headers.keys())
            
            if('x-frame-options' not in [h.lower() for h in headers_list]):
                findings.append({
                    "module_name": "http_headers",
                    "issue": "X-Frame-Options header not found",
                    "evidence": "X-Frame-Options header not found in response headers",
                    "severity_hint": "medium"
                })
        except Exception:
            return []
        return findings
