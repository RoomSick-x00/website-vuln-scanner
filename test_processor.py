from workers.processor import run_scan

# Test TLS scanner
print("\n--- TLS SCAN ---")
result = run_scan("https://example.com", "tls", 10)
print(f"Status: {result['status']}")
print(f"Findings: {len(result['findings'])}")
for f in result['findings']:
    print(f"  [{f['severity']}] {f['issue']}")

# Test HTTP Headers scanner
print("\n--- HTTP HEADERS SCAN ---")
result = run_scan("https://example.com", "http_headers", 10)
print(f"Status: {result['status']}")
print(f"Findings: {len(result['findings'])}")
for f in result['findings']:
    print(f"  [{f['severity']}] {f['issue']}")

# Test unknown task_type
print("\n--- UNKNOWN TASK TYPE ---")
result = run_scan("https://example.com", "unknown", 10)
print(f"Status: {result['status']}")
print(f"Error: {result['error']}")