# test_tls.py
from workers.scanner_modules.tls import TLSScanner

scanner = TLSScanner()

target = "https://expired.badssl.com"
results = scanner.scan(target, timeout=5)

for finding in results:
    print(finding)
    


# python -m workers.scanner_modules.test_tls -> run using 