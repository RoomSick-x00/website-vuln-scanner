from workers.processor import run_scan

tests = [
    ("test-001", "tls", "https://example.com"),
    ("test-002", "http_headers", "https://example.com"),
    ("test-003", "xss", "https://google.com/search?q=test"),
    ("test-004", "dns", "https://github.com"),
    ("test-005", "unknown", "https://example.com"),
]

for scan_id, task_type, url in tests:
    print(f"\n--- {task_type.upper()} SCAN ---")
    result = run_scan.run(scan_id, task_type, url)
    print(f"Status: {result['status']}")
    print(f"Findings: {len(result['findings'])}")
    for f in result['findings']:
        print(f"  [{f['severity']}] {f['issue']}")
        
# $env:PYTHONPATH = "C:\Users\mailp\OneDrive\Desktop\Project V\website-vuln-scanner;C:\Users\mailp\OneDrive\Desktop\Project V\website-vuln-scanner\backend"
# $env:DATABASE_URL = "postgresql://postgres:postgres@localhost:5432/scanner_db"
# python test_processor.py