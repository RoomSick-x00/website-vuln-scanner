# scanners/http_headers.py

from scanners.base import BaseScanner

class HTTPHeadersScanner(BaseScanner):
    name = "http_headers"

    def scan(self, target: str, timeout: int):
        findings = []
        try:
            response = requests.get(target)
            headers_list = list(response.headers.keys().lower())
            
            if('x-frame-options' not in headers_list):
                findings.append({
                    "module_name": "HTTP Headers",
                    "issue": "X-Frame-Options header not found",
                    "evidence": "X-Frame-Options header not found in response headers",
                    "severity_hint": "low"
                })
        except Exception:
            return []
        return findings
