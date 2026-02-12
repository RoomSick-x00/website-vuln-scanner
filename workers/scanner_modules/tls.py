from urllib.parse import urlparse
import socket
import ssl

class TLSScanner():
    name = "tls"
    
    def scan(self, target: str, timeout: int):
        findings = []
        
        parsed = urlparse(target)
        host = parsed.hostname
        port = parsed.port or 443
        
        context = ssl.create_default_context()

        sock = socket.create_connection((host, port), timeout=timeout)
        tls_sock = context.wrap_socket(sock, server_hostname=host)

        tls_version = tls_sock.version()

        findings.append({
            "module_name": self.name,
            "issue": "TLS connection established",
            "evidence": f"Negotiated protocol: {tls_version}",
            "severity_hint": "info"
        })

        tls_sock.close()

        return findings 