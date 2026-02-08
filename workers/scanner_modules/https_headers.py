# scanners/http_headers.py
import requests

from scanners.base import BaseScanner

headers = [
    {
        "name": "Cache-Control",
        "value": "no-store, max-age=0",
        "severity": "low",
        "description": "Prevents sensitive data from being cached by browsers or proxies."
    },
    {
        "name": "Clear-Site-Data",
        "value": "\"cache\",\"cookies\",\"storage\"",
        "severity": "low",
        "description": "Clears client-side storage to protect user data."
    },
    {
        "name": "Content-Security-Policy",
        "value": "default-src 'self'; form-action 'self'; base-uri 'self'; object-src 'none'; frame-ancestors 'none'; upgrade-insecure-requests",
        "severity": "high",
        "description": "Mitigates XSS, data injection, and clickjacking attacks."
    },
    {
        "name": "Cross-Origin-Embedder-Policy",
        "value": "require-corp",
        "severity": "high",
        "description": "Prevents loading cross-origin resources without explicit permission."
    },
    {
        "name": "Cross-Origin-Opener-Policy",
        "value": "same-origin",
        "severity": "high",
        "description": "Isolates browsing context to prevent cross-origin data leaks."
    },
    {
        "name": "Cross-Origin-Resource-Policy",
        "value": "same-origin",
        "severity": "high",
        "description": "Prevents other origins from reading responses."
    },
    {
        "name": "Permissions-Policy",
        "value": "accelerometer=(), autoplay=(), camera=(), cross-origin-isolated=(), display-capture=(), encrypted-media=(), fullscreen=(), geolocation=(), gyroscope=(), keyboard-map=(), magnetometer=(), microphone=(), midi=(), payment=(), picture-in-picture=(), publickey-credentials-get=(), screen-wake-lock=(), sync-xhr=(self), usb=(), web-share=(), xr-spatial-tracking=(), clipboard-read=(), clipboard-write=(), gamepad=(), hid=(), idle-detection=(), interest-cohort=(), serial=(), unload=()",
        "severity": "medium",
        "description": "Restricts access to powerful browser features."
    },
    {
        "name": "Referrer-Policy",
        "value": "no-referrer",
        "severity": "medium",
        "description": "Controls how much referrer information is sent with requests."
    },
    {
        "name": "Strict-Transport-Security",
        "value": "max-age=31536000; includeSubDomains",
        "severity": "high",
        "description": "Enforces HTTPS and prevents SSL stripping attacks."
    },
    {
        "name": "X-Content-Type-Options",
        "value": "nosniff",
        "severity": "medium",
        "description": "Prevents MIME type sniffing by browsers."
    },
    {
        "name": "X-DNS-Prefetch-Control",
        "value": "off",
        "severity": "low",
        "description": "Controls DNS prefetching to improve privacy."
    },
    {
        "name": "X-Frame-Options",
        "value": "deny",
        "severity": "medium",
        "description": "Prevents clickjacking by disallowing framing."
    },
    {
        "name": "X-Permitted-Cross-Domain-Policies",
        "value": "none",
        "severity": "low",
        "description": "Restricts Adobe Flash and PDF cross-domain access."
    }
]

class HTTPHeadersScanner(BaseScanner):
    
    name = "http_headers"

    def scan(self, target: str, timeout: int):
        findings = []
        try:
            response = requests.get(target, timeout=timeout)
            response_headers = {h.lower() for h in response.headers.keys()}
            
            for header in headers:
                header_name = header["name"].lower()

                if header_name not in response_headers:
                    findings.append({
                        "module_name": self.name,
                        "issue": f"{header['name']} header not found",
                        "evidence": f"{header['name']} header not found in response headers",
                        "severity_hint": header["severity"]
                    })

        except Exception:
            return []
        return findings

# for header in headers:
#     print(header["value"])

