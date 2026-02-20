def submit_scan(url):
    """
    Simulates submitting a scan.
    Later, this will call api.submit_scan(url)
    """
    scan_id = "123"  # fake for now
    return {
        "scan_id": scan_id,
        "message": "Scan submitted successfully"
    }


def check_status(scan_id):
    """
    Simulates checking scan status.
    """
    return {
        "scan_id": scan_id,
        "status": "running"
    }


def get_results(scan_id):
    """
    Simulates fetching scan results.
    """
    return {
        "scan_id": scan_id,
        "results": {
            "XSS": "VULNERABLE",
            "SQL Injection": "SAFE",
            "CSRF": "SAFE"
        }
    }
