from tasks.celery_app import app
from workers.scanner_modules.https_headers import HTTPHeadersScanner

@app.task
def run_http_headers_scan(url):
    scanner = HTTPHeadersScanner()
    result = scanner.scan(target=url, timeout=5)
    return result
