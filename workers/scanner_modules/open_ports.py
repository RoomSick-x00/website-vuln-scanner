# scanners/open_ports.py

from scanners.base import BaseScanner

class OpenPortsScanner(BaseScanner):
    name = "open_ports"

    def scan(self, target: str, timeout: int):
        findings = []
        try:
            # logic later
            pass
        except Exception:
            return []
        return findings
