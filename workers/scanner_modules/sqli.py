# scanners/sqli.py

from scanners.base import BaseScanner

class SQLiScanner(BaseScanner):
    name = "sqli"

    def scan(self, target: str, timeout: int):
        findings = []
        try:
            # logic later (boolean/time-based safe checks)
            pass
        except Exception:
            return []
        return findings
