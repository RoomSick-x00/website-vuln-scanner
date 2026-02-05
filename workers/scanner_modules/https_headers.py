# scanners/http_headers.py

from scanners.base import BaseScanner

class HTTPHeadersScanner(BaseScanner):
    name = "http_headers"

    def scan(self, target: str, timeout: int):
        findings = []
        try:
            # logic later
            pass
        except Exception:
            return []
        return findings
