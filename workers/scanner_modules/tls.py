from __future__ import annotations

import socket
import ssl
from datetime import datetime, timezone
from urllib.parse import urlparse


class TLSScanner:
    name = "tls"

    def scan(self, target: str, timeout: int):
        """
        Sequential checks (as requested):
        1) Negotiate TLS + report negotiated protocol
        2) Certificate observations (issuer, expiry, subject/hostname match)
        3) Cryptographic details (cipher suite, TLS 1.0 probing, weak ciphers)
        """
        findings: list[dict] = []

        parsed = urlparse(target)
        host = parsed.hostname
        port = parsed.port or 443

        if not host:
            return findings

        # Step 1 + 2: initial handshake (no CA verification here)
        base_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        base_context.check_hostname = False
        base_context.verify_mode = ssl.CERT_NONE

        cert_findings: list[dict] = []
        try:
            with socket.create_connection((host, port), timeout=timeout) as sock:
                with base_context.wrap_socket(sock, server_hostname=host) as tls_sock:
                    tls_version = tls_sock.version()
                    findings.append(
                        {
                            "module_name": self.name,
                            "issue": "TLS protocol negotiated",
                            "evidence": f"Negotiated protocol: {tls_version}",
                            "severity_hint": "info",
                        }
                    )

                    cert_findings = self._check_certificate(tls_sock, host)
                    findings.extend(cert_findings)

        except ssl.SSLError as e:
            findings.append(
                {
                    "module_name": self.name,
                    "issue": "TLS handshake failed",
                    "evidence": str(e),
                    "severity_hint": "medium",
                }
            )
            return findings
        except OSError as e:
            # Includes timeouts / connection refused / DNS issues
            findings.append(
                {
                    "module_name": self.name,
                    "issue": "TLS connection failed",
                    "evidence": str(e),
                    "severity_hint": "medium",
                }
            )
            return findings

        # If certificate check found critical issues, skip cryptographic details
        if any(f.get("severity_hint") == "high" for f in cert_findings):
            return findings

        # Step 3: Cryptographic details (new connection)
        findings.extend(self._check_cryptographic_details(host, port, timeout))
        return findings

    def _check_certificate(self, tls_sock: ssl.SSLSocket, host: str):
        findings: list[dict] = []

        try:
            cert = tls_sock.getpeercert()
        except Exception as e:
            return [
                {
                    "module_name": self.name,
                    "issue": "Certificate check failed",
                    "evidence": f"Error retrieving certificate: {e}",
                    "severity_hint": "medium",
                }
            ]

        if not cert:
            return [
                {
                    "module_name": self.name,
                    "issue": "Certificate not available",
                    "evidence": "Could not retrieve parsed certificate details via getpeercert()",
                    "severity_hint": "medium",
                }
            ]

        # Expiration observation
        not_after = cert.get("notAfter")
        if not_after:
            try:
                exp_date = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
                days_until_expiry = int((exp_date - datetime.now(timezone.utc)).total_seconds() // 86400)

                if days_until_expiry < 0:
                    findings.append(
                        {
                            "module_name": self.name,
                            "issue": "Certificate expired",
                            "evidence": f"Certificate expired on {not_after}",
                            "severity_hint": "high",
                        }
                    )
                elif days_until_expiry < 30:
                    findings.append(
                        {
                            "module_name": self.name,
                            "issue": "Certificate expiring soon",
                            "evidence": f"Certificate expires in {days_until_expiry} days ({not_after})",
                            "severity_hint": "medium",
                        }
                    )
                else:
                    findings.append(
                        {
                            "module_name": self.name,
                            "issue": "Certificate expiration check",
                            "evidence": f"Certificate valid until {not_after} ({days_until_expiry} days remaining)",
                            "severity_hint": "info",
                        }
                    )
            except ValueError:
                findings.append(
                    {
                        "module_name": self.name,
                        "issue": "Certificate expiration date parsing failed",
                        "evidence": f"Could not parse expiration date: {not_after}",
                        "severity_hint": "low",
                    }
                )

        # Issuer observation
        issuer = cert.get("issuer")
        if issuer:
            issuer_str = ", ".join(f"{k}={v}" for rdn in issuer for k, v in rdn)
            findings.append(
                {
                    "module_name": self.name,
                    "issue": "Certificate issuer",
                    "evidence": f"Issuer: {issuer_str}",
                    "severity_hint": "info",
                }
            )

        # Subject + hostname match observation
        subject = cert.get("subject")
        if subject:
            subject_str = ", ".join(f"{k}={v}" for rdn in subject for k, v in rdn)
            host_matches = self._cert_matches_host(cert, host)

            if not host_matches:
                findings.append(
                    {
                        "module_name": self.name,
                        "issue": "Certificate subject mismatch",
                        "evidence": f"Certificate subject '{subject_str}' does not match hostname '{host}'",
                        "severity_hint": "high",
                    }
                )
            else:
                findings.append(
                    {
                        "module_name": self.name,
                        "issue": "Certificate subject",
                        "evidence": f"Subject: {subject_str}",
                        "severity_hint": "info",
                    }
                )

        return findings

    def _cert_matches_host(self, cert: dict, host: str) -> bool:
        """
        Best-effort hostname matching.
        Uses stdlib match_hostname (deprecated but widely available) to support wildcards.
        """
        try:
            ssl.match_hostname(cert, host)
            return True
        except Exception:
            return False

    def _check_cryptographic_details(self, host: str, port: int, timeout: int):
        findings: list[dict] = []

        # Cipher suite observation
        try:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE

            with socket.create_connection((host, port), timeout=timeout) as sock:
                with ctx.wrap_socket(sock, server_hostname=host) as tls_sock:
                    cipher = tls_sock.cipher()
                    if cipher:
                        cipher_name = cipher[0]
                        findings.append(
                            {
                                "module_name": self.name,
                                "issue": "Cipher suite",
                                "evidence": f"Negotiated cipher: {cipher_name}",
                                "severity_hint": "info",
                            }
                        )

                        # Heuristic weak-cipher markers (string-based)
                        weak_markers = [
                            "RC4",
                            "DES",
                            "3DES",
                            "MD5",
                            "SHA1",
                            "NULL",
                            "EXPORT",
                            "ANON",
                            "ADH",
                            "AECDH",
                            "CBC",
                            "TLS_RSA",
                        ]
                        cipher_upper = cipher_name.upper()
                        weak_found = [m for m in weak_markers if m in cipher_upper]
                        if weak_found:
                            findings.append(
                                {
                                    "module_name": self.name,
                                    "issue": "Weak cipher detected",
                                    "evidence": (
                                        f"Cipher '{cipher_name}' contains weak components: {', '.join(weak_found)}"
                                    ),
                                    "severity_hint": "high",
                                }
                            )
        except Exception as e:
            findings.append(
                {
                    "module_name": self.name,
                    "issue": "Cipher suite check failed",
                    "evidence": str(e),
                    "severity_hint": "medium",
                }
            )

        # TLS 1.0 probing
        try:
            if self._probe_tls10(host, port, timeout):
                findings.append(
                    {
                        "module_name": self.name,
                        "issue": "TLS 1.0 enabled",
                        "evidence": "Server accepts TLS 1.0 connections (deprecated and insecure)",
                        "severity_hint": "high",
                    }
                )
            else:
                findings.append(
                    {
                        "module_name": self.name,
                        "issue": "TLS 1.0 check",
                        "evidence": "TLS 1.0 is not supported (good)",
                        "severity_hint": "info",
                    }
                )
        except Exception as e:
            findings.append(
                {
                    "module_name": self.name,
                    "issue": "TLS 1.0 probe failed",
                    "evidence": str(e),
                    "severity_hint": "medium",
                }
            )

        return findings

    def _probe_tls10(self, host: str, port: int, timeout: int) -> bool:
        """
        Probe whether the server will negotiate TLS 1.0.
        Returns True only if the negotiated version is TLSv1 / TLSv1.0.
        """
        with socket.create_connection((host, port), timeout=timeout) as sock:
            # Prefer the min/max TLSVersion API when available.
            try:
                ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                ctx.minimum_version = ssl.TLSVersion.TLSv1
                ctx.maximum_version = ssl.TLSVersion.TLSv1
            except Exception:
                # Fallback: attempt to allow TLSv1 and disable higher versions.
                ctx = ssl.SSLContext(ssl.PROTOCOL_TLS)
                for opt in ("OP_NO_TLSv1_1", "OP_NO_TLSv1_2", "OP_NO_TLSv1_3"):
                    val = getattr(ssl, opt, None)
                    if val is not None:
                        ctx.options |= val
                op_no_tlsv1 = getattr(ssl, "OP_NO_TLSv1", None)
                if op_no_tlsv1 is not None:
                    ctx.options &= ~op_no_tlsv1

            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE

            with ctx.wrap_socket(sock, server_hostname=host) as tls_sock:
                version = tls_sock.version()
                return version in ("TLSv1", "TLSv1.0")

from multiprocessing import context
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
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE #creates secure TLS configuration
        
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
        cert = tls_sock.getpeercert(binary_form=False)

        # If parsed certificate is empty, fallback to manual decode
        if not cert:
            cert_bin = tls_sock.getpeercert(binary_form=True)
            if not cert_bin:
                findings.append({
                    "module_name": self.name,
                    "issue": "Certificate not available",
                    "evidence": "Could not retrieve certificate information",
                    "severity_hint": "medium"
                })
                return findings

            # Convert DER → PEM → decode
            pem_cert = ssl.DER_cert_to_PEM_cert(cert_bin)
            cert = ssl._ssl._test_decode_cert(pem_cert)
            
        not_after = cert.get('notAfter')
        if not_after:
            try:
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

        issuer = cert.get('issuer')
        if issuer:
            issuer_str = ', '.join([f"{k}={v}" for item in issuer for k, v in item])
            findings.append({
                "module_name": self.name,
                "issue": "Certificate issuer",
                "evidence": f"Issuer: {issuer_str}",
                "severity_hint": "info"
            })

        subject = cert.get('subject')
        if subject:
            subject_str = ', '.join([f"{k}={v}" for item in subject for k, v in item])

            subjectAltName = cert.get('subjectAltName', [])
            host_matched = False

            # Check SAN first
            for san_type, san_value in subjectAltName:
                if san_type == 'DNS' and san_value == host:
                    host_matched = True
                    break

            # Fallback to commonName
            if not host_matched:
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
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
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