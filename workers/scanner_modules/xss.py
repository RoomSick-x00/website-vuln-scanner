# scanners/xss.py

from scanners.base import BaseScanner

class XSSScanner(BaseScanner):
    name = "xss"

    def scan(self, target: str, timeout: int):
        findings = []
        try:
            # logic later (reflected tests only)
            pass
        except Exception:
            return []
        return findings
