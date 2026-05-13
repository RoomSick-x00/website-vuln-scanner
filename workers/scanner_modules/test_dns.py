import sys
from workers.scanner_modules.dns import DNSScanner

target = sys.argv[1] if len(sys.argv) > 1 else "https://example.com"
scanner = DNSScanner()
findings = scanner.safe_scan(target)

print(f"\nTarget: {target}")
print(f"Findings: {len(findings)}\n")
for f in findings:
    print(f"  [{f['severity']}] {f['issue']}")
    print(f"  Evidence: {f['evidence'][:80]}")
    print()