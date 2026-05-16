import os
import requests

BASE_URL = os.getenv("BACKEND_URL", "http://localhost:8000")


def submit_scan(url):
    return submit_scan_with_type(url, "quick")


def submit_scan_with_type(url, scan_type):
    payload = {
        "target": url,
        "scan_type": scan_type
    }
    try:
        response = requests.post(f"{BASE_URL}/scans/", json=payload)
        if response.status_code != 200:
            return {"error": f"Backend error: {response.text}"}
        return response.json()
    except Exception as e:
        return {"error": str(e)}


def get_results(scan_id):
    try:
        response = requests.get(f"{BASE_URL}/scans/{scan_id}")
        if response.status_code != 200:
            return {"error": f"Backend error: {response.text}"}
        return response.json()
    except Exception as e:
        return {"error": str(e)}


def get_status(scan_id):
    response = requests.get(f"{BASE_URL}/scans/{scan_id}")
    return response.json()


def check_status(scan_id):
    return get_status(scan_id)  