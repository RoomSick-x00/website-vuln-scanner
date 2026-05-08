from . import api

def submit_scan(url):
    return api.submit_scan(url)

def get_status(scan_id):
    return api.get_status(scan_id)

def get_results(scan_id):
    return api.get_results(scan_id)