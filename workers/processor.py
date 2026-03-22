from workers.scanner_modules.tls import TLSScanner
from workers.scanner_modules.https_headers import HTTPHeadersScanner

# way to map a task_type string to the right scanner class.
SCANNER_REGISTRY = {
    "tls": TLSScanner(),
    "http_headers": HTTPHeadersScanner(),
}