# scanners/dir_listing.py

from scanners.base import BaseScanner

class DirectoryListingScanner(BaseScanner):
    name = "dir_listing"

    def scan(self, target: str, timeout: int):
        findings = []
        try:
            # logic later
            pass
        except Exception:
            return []
        return findings
