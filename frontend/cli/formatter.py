def _scan_id(data):
    return data.get("scan_id") or data.get("id") or "unknown"


def _status(data):
    return str(data.get("status", "unknown")).upper()


def _print_error(data):
    if data.get("error"):
        print(f"Error: {data['error']}")
        return True
    return False


def format_submit_response(data):
    if _print_error(data):
        return
    print("Scan submitted successfully")
    print(f"Scan ID: {_scan_id(data)}")


def format_status_response(data):
    if _print_error(data):
        return
    print(f"Scan ID : {_scan_id(data)}")
    print(f"Status  : {_status(data)}")


def format_results_response(data):
    if _print_error(data):
        return

    findings = data.get("results") or data.get("findings") or []
    grouped = data.get("grouped") or {}

    print(f"Scan ID : {_scan_id(data)}")
    print(f"Status  : {_status(data)}")
    print(f"Target  : {data.get('target', 'unknown')}")
    print(f"Findings: {len(findings)}")

    if grouped:
        print("")
        for category, category_findings in grouped.items():
            print(f"{category}: {len(category_findings)}")
