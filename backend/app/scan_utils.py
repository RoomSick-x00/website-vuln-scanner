import hashlib
from collections import defaultdict

ALL_MODULES = ["tls", "http_headers", "dns", "xss"]

SCAN_MODES = {
    "quick": ["tls", "http_headers", "dns"],
    "full": ["tls", "http_headers", "dns", "xss"],
}

MODULE_LABELS = {
    "tls": "TLS / SSL",
    "http_headers": "HTTP Headers",
    "dns": "DNS Configuration",
    "xss": "XSS",
}


def generate_verification_token(domain: str) -> str:
    return "vuln-verify-" + hashlib.sha256(domain.encode()).hexdigest()[:16]


def extract_domain(target: str) -> str:
    from urllib.parse import urlparse

    parsed = urlparse(target if "://" in target else f"https://{target}")
    return (parsed.netloc or target).lower().removeprefix("www.")


def resolve_scan_modules(scan_mode: str, modules: list[str] | None = None) -> list[str]:
    if modules:
        return [m for m in modules if m in ALL_MODULES]
    if scan_mode in SCAN_MODES:
        return SCAN_MODES[scan_mode]
    if scan_mode and "," in scan_mode:
        return [m.strip() for m in scan_mode.split(",") if m.strip() in ALL_MODULES]
    return SCAN_MODES["quick"]


def module_lists(scan_mode: str, modules: list[str] | None = None) -> tuple[list[str], list[str]]:
    ran = resolve_scan_modules(scan_mode, modules)
    skipped = [m for m in ALL_MODULES if m not in ran]
    return ran, skipped


def group_findings(findings: list[dict]) -> dict[str, list[dict]]:
    grouped: dict[str, list[dict]] = defaultdict(list)
    for finding in findings or []:
        module = finding.get("module_name") or finding.get("task_type") or "unknown"
        grouped[module].append(finding)
    return dict(grouped)
