import os
import requests

BASE_URL = os.getenv("BACKEND_URL", "http://localhost:8000")

def submit_scan(url):
    res = requests.post(f"{BASE_URL}/scans/", json={
        "target": url,
        "scan_mode": "quick"
    })
    return res.json()

def get_status(scan_id):
    res = requests.get(f"{BASE_URL}/scans/{scan_id}")
    return res.json()

def get_results(scan_id):
    res = requests.get(f"{BASE_URL}/scans/{scan_id}")
    return res.json()
