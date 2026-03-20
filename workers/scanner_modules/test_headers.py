import sys
from workers.scanner_modules.https_headers import HTTPHeadersScanner

target = sys.argv[1] if len(sys.argv) > 1 else "https://example.com"

scanner = HTTPHeadersScanner()
findings = scanner.safe_scan(target)

for f in findings:
    print(f)