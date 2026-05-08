import sys
from workers.scanner_modules.xss import XSSScanner

target = sys.argv[1] if len(sys.argv) > 1 else "http://testphp.vulnweb.com"

scanner = XSSScanner()
findings = scanner.safe_scan(target)

print(f"\nTarget: {target}")
print(f"Findings: {len(findings)}\n")

for f in findings:
    print(f"  [{f['severity']}] {f['issue']}")
    print(f"  Evidence: {f['evidence']}")
    print()
    
#python -m workers.scanner_modules.test_xss "https://httpbin.org/forms/post"