from workers.processor import run_scan

tests = [
    (1, "tls", "https://example.com"),
    (2, "http_headers", "https://example.com"),
    (3, "xss", "https://google.com/search?q=test"),
    (4, "dns", "https://github.com"),
    (5, "unknown", "https://example.com"),
]

for scan_id, task_type, url in tests:
    print(f"\n--- {task_type.upper()} SCAN ---")
    result = run_scan.run(scan_id, task_type, url)
    print(f"Status: {result['status']}")
    print(f"Findings: {len(result['findings'])}")
    for f in result['findings']:
        print(f"  [{f['severity']}] {f['issue']}")