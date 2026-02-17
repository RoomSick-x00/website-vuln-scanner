from urllib.parse import urlparse #url disection tool
import socket
import ssl

class TLSScanner():
    name = "tls"
    
    def scan(self, target: str, timeout: int):
        findings = []
        
        parsed = urlparse(target)
        host = parsed.hostname
        port = parsed.port or 443
        
        # A configuration object that defines how TLS should behave.
        context = ssl.create_default_context() #creates secure TLS configuration

        sock = socket.create_connection((host, port), timeout=timeout) #opens a tcp connection to the server
        tls_sock = context.wrap_socket(sock, server_hostname=host) # performs tls handshake, negotiates tls version, verifies certificate 

        tls_version = tls_sock.version()

        findings.append({
            "module_name": self.name,
            "issue": "TLS connection established",
            "evidence": f"Negotiated protocol: {tls_version}",
            "severity_hint": "info"
        })

        tls_sock.close()

        return findings 