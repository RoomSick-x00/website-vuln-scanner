import requests

BASE_URL = "http://backend:8000"

def submit_scan(url):
    res = requests.post(f"{BASE_URL}/scans", json={
        "target": url,
        "scan_type": "full"
    })
    return res.json()

def get_status(scan_id):
    res = requests.get(f"{BASE_URL}/scans/{scan_id}")
    return res.json()

def get_results(scan_id):
    res = requests.get(f"{BASE_URL}/scans/{scan_id}/report")
    return res.json()