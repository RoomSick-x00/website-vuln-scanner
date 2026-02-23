# test_tls.py
from workers.scanner_modules.tls import TLSScanner

scanner = TLSScanner()

target = "https://google.com"
results = scanner.scan(target, timeout=5)

for finding in results:
    print(finding)