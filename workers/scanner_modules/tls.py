from urllib.parse import urlparse #url disection tool
import socket
import ssl
from datetime import datetime

class TLSScanner():
    name = "tls"
    
    def scan(self, target: str, timeout: int):
        findings = []
        
        parsed = urlparse(target)
        host = parsed.hostname
        port = parsed.port or 443
        
        # A configuration object that defines how TLS should behave.
        context = ssl.create_default_context() #creates secure TLS configuration
        
        if not host:
            return findings
        
        try:
            sock = socket.create_connection((host, port), timeout=timeout) #opens a tcp connection to the server
        except OSError:
            return findings
            
        try:
            tls_sock = context.wrap_socket(sock, server_hostname=host) # performs tls handshake, negotiates tls version, verifies certificate 
        except ssl.SSLError as e:
            findings.append({
                "module_name": self.name,
                "issue": "TLS handshake failed",
                "evidence": str(e),
                "severity_hint": "medium"
            })
            sock.close()
            return findings

        # Step 1: Check TLS version
        tls_version = tls_sock.version()
        findings.append({
            "module_name": self.name,
            "issue": "TLS protocol negotiated",
            "evidence": f"Negotiated protocol: {tls_version}",
            "severity_hint": "info"
        })

        # Step 2: Certificate observations (only if TLS version check passed)
        cert_findings = self._check_certificate(tls_sock, host)
        findings.extend(cert_findings)
        
        # If certificate check found critical issues, skip cryptographic details
        if any(f.get("severity_hint") == "high" for f in cert_findings):
            tls_sock.close()
            return findings

        # Step 3: Check cryptographic details (only if certificate check passed)
        crypto_findings = self._check_cryptographic_details(host, port, timeout)
        findings.extend(crypto_findings)

        tls_sock.close()

        return findings
    
    def _check_certificate(self, tls_sock, host):
        """Check certificate issuer, expiration date, and subject"""
        findings = []
        
        try:
            cert = tls_sock.getpeercert()
            if not cert:
                findings.append({
                    "module_name": self.name,
                    "issue": "Certificate not available",
                    "evidence": "Could not retrieve certificate information",
                    "severity_hint": "medium"
                })
                return findings
            
            # Check certificate expiration
            not_after = cert.get('notAfter')
            if not_after:
                try:
                    # Parse date format: "Dec 31 23:59:59 2024 GMT"
                    exp_date = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
                    days_until_expiry = (exp_date - datetime.utcnow()).days
                    
                    if days_until_expiry < 0:
                        findings.append({
                            "module_name": self.name,
                            "issue": "Certificate expired",
                            "evidence": f"Certificate expired on {not_after}",
                            "severity_hint": "high"
                        })
                    elif days_until_expiry < 30:
                        findings.append({
                            "module_name": self.name,
                            "issue": "Certificate expiring soon",
                            "evidence": f"Certificate expires in {days_until_expiry} days ({not_after})",
                            "severity_hint": "medium"
                        })
                    else:
                        findings.append({
                            "module_name": self.name,
                            "issue": "Certificate expiration check",
                            "evidence": f"Certificate valid until {not_after} ({days_until_expiry} days remaining)",
                            "severity_hint": "info"
                        })
                except ValueError:
                    findings.append({
                        "module_name": self.name,
                        "issue": "Certificate expiration date parsing failed",
                        "evidence": f"Could not parse expiration date: {not_after}",
                        "severity_hint": "low"
                    })
            
            # Check certificate issuer
            issuer = cert.get('issuer')
            if issuer:
                issuer_str = ', '.join([f"{k}={v}" for item in issuer for k, v in item])
                findings.append({
                    "module_name": self.name,
                    "issue": "Certificate issuer",
                    "evidence": f"Issuer: {issuer_str}",
                    "severity_hint": "info"
                })
            
            # Check certificate subject
            subject = cert.get('subject')
            if subject:
                subject_str = ', '.join([f"{k}={v}" for item in subject for k, v in item])
                # Check if subject matches hostname
                subjectAltName = cert.get('subjectAltName', [])
                host_matched = False
                
                if subjectAltName:
                    for san_type, san_value in subjectAltName:
                        if san_type == 'DNS' and san_value == host:
                            host_matched = True
                            break
                
                if not host_matched:
                    # Check commonName in subject
                    for item in subject:
                        for key, value in item:
                            if key == 'commonName' and value == host:
                                host_matched = True
                                break
                    
                    if not host_matched:
                        findings.append({
                            "module_name": self.name,
                            "issue": "Certificate subject mismatch",
                            "evidence": f"Certificate subject '{subject_str}' does not match hostname '{host}'",
                            "severity_hint": "high"
                        })
                    else:
                        findings.append({
                            "module_name": self.name,
                            "issue": "Certificate subject",
                            "evidence": f"Subject: {subject_str}",
                            "severity_hint": "info"
                        })
                else:
                    findings.append({
                        "module_name": self.name,
                        "issue": "Certificate subject",
                        "evidence": f"Subject: {subject_str}",
                        "severity_hint": "info"
                    })
            
        except Exception as e:
            findings.append({
                "module_name": self.name,
                "issue": "Certificate check failed",
                "evidence": f"Error during certificate check: {str(e)}",
                "severity_hint": "medium"
            })
        
        return findings
    
    def _check_cryptographic_details(self, host, port, timeout):
        """Check cipher suite, TLS 1.0 support, and weak ciphers"""
        findings = []
        
        try:
            # Get cipher suite from existing connection
            sock = socket.create_connection((host, port), timeout=timeout)
            context = ssl.create_default_context()
            tls_sock = context.wrap_socket(sock, server_hostname=host)
            
            cipher = tls_sock.cipher()
            if cipher:
                cipher_name = cipher[0]
                findings.append({
                    "module_name": self.name,
                    "issue": "Cipher suite",
                    "evidence": f"Negotiated cipher: {cipher_name}",
                    "severity_hint": "info"
                })
                
                # Check for weak ciphers
                weak_ciphers = [
                    'RC4', 'DES', 'MD5', 'SHA1', 'NULL', 'EXPORT', 
                    'ANON', 'ADH', 'AECDH', 'CBC', '3DES', 'TLS_RSA'
                ]
                cipher_upper = cipher_name.upper()
                weak_found = [w for w in weak_ciphers if w in cipher_upper]
                
                if weak_found:
                    findings.append({
                        "module_name": self.name,
                        "issue": "Weak cipher detected",
                        "evidence": f"Cipher '{cipher_name}' contains weak components: {', '.join(weak_found)}",
                        "severity_hint": "high"
                    })
            
            tls_sock.close()
            
            # Probe for TLS 1.0 support
            tls10_supported = self._probe_tls10(host, port, timeout)
            if tls10_supported:
                findings.append({
                    "module_name": self.name,
                    "issue": "TLS 1.0 enabled",
                    "evidence": "Server accepts TLS 1.0 connections (deprecated and insecure)",
                    "severity_hint": "high"
                })
            else:
                findings.append({
                    "module_name": self.name,
                    "issue": "TLS 1.0 check",
                    "evidence": "TLS 1.0 is not supported (good)",
                    "severity_hint": "info"
                })
            
        except Exception as e:
            findings.append({
                "module_name": self.name,
                "issue": "Cryptographic details check failed",
                "evidence": f"Error during cryptographic check: {str(e)}",
                "severity_hint": "medium"
            })
        
        return findings
    
    def _probe_tls10(self, host, port, timeout):
        """Probe if server accepts TLS 1.0 connections"""
        try:
            sock = socket.create_connection((host, port), timeout=timeout)
            # Create context that allows TLS 1.0
            try:
                # Python 3.7+ approach
                context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                context.minimum_version = ssl.TLSVersion.MINIMUM_SUPPORTED
                context.maximum_version = ssl.TLSVersion.TLSv1
            except AttributeError:
                # Fallback for older Python versions
                context = ssl.SSLContext(ssl.PROTOCOL_TLS)
                # Try to set TLS 1.0 as maximum
                try:
                    context.options &= ~ssl.OP_NO_TLSv1
                    context.options |= ssl.OP_NO_TLSv1_1
                    context.options |= ssl.OP_NO_TLSv1_2
                    context.options |= ssl.OP_NO_TLSv1_3
                except AttributeError:
                    pass
            
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            tls_sock = context.wrap_socket(sock, server_hostname=host)
            version = tls_sock.version()
            tls_sock.close()
            # Check if negotiated version is TLS 1.0
            return version in ['TLSv1', 'TLSv1.0']
        except (ssl.SSLError, OSError, AttributeError):
            return False 