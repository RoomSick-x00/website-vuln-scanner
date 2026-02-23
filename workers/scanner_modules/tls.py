from urllib.parse import urlparse
import socket
import ssl
from datetime import datetime, timezone

# Optional but recommended
try:
    from cryptography import x509
    from cryptography.x509.oid import NameOID
    from cryptography.hazmat.primitives.asymmetric import rsa
    CRYPTO_AVAILABLE = True
except ImportError:
    CRYPTO_AVAILABLE = False


class TLSScanner:
    name = "tls"

    def scan(self, target: str, timeout: int):
        findings = []

        parsed = urlparse(target)
        host = parsed.hostname
        port = parsed.port or 443

        if not host:
            return findings

        # Use properly initialized client context
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

        sock = None
        tls_sock = None

        try:
            sock = socket.create_connection((host, port), timeout=timeout)
            tls_sock = context.wrap_socket(sock, server_hostname=host)

            # TLS version
            findings.append({
                "module_name": self.name,
                "issue": "TLS protocol negotiated",
                "evidence": f"Negotiated protocol: {tls_sock.version()}",
                "severity_hint": "info"
            })

            # Certificate checks
            findings.extend(self._check_certificate(tls_sock, host))

            # Cipher + Forward Secrecy
            findings.extend(self._check_cipher(tls_sock))

            # TLS version matrix
            findings.extend(self._probe_tls_versions(host, port, timeout))
            
            findings.extend(self._check_forward_secrecy_support(host, port, timeout))

        except ssl.SSLError as e:
            findings.append({
                "module_name": self.name,
                "issue": "TLS handshake failed",
                "evidence": str(e),
                "severity_hint": "high"
            })

        except OSError as e:
            findings.append({
                "module_name": self.name,
                "issue": "Connection failed",
                "evidence": str(e),
                "severity_hint": "medium"
            })

        finally:
            if tls_sock:
                tls_sock.close()
            elif sock:
                sock.close()

        return findings

    def _check_certificate(self, tls_sock, host):
        findings = []

        try:
            cert_der = tls_sock.getpeercert(binary_form=True)

            if not cert_der:
                findings.append({
                    "module_name": self.name,
                    "issue": "Certificate not available",
                    "evidence": "Could not retrieve certificate information",
                    "severity_hint": "medium"
                })
                return findings

            if not CRYPTO_AVAILABLE:
                findings.append({
                    "module_name": self.name,
                    "issue": "Cryptography library missing",
                    "evidence": "Install 'cryptography' to enable certificate analysis",
                    "severity_hint": "low"
                })
                return findings

            cert_obj = x509.load_der_x509_certificate(cert_der)

            # Expiration
            exp_date = cert_obj.not_valid_after_utc
            now = datetime.now(timezone.utc)
            days_until_expiry = (exp_date - now).days

            if days_until_expiry < 0:
                issue = "Certificate expired"
                severity = "high"
            elif days_until_expiry < 30:
                issue = "Certificate expiring soon"
                severity = "medium"
            else:
                issue = "Certificate valid"
                severity = "info"

            findings.append({
                "module_name": self.name,
                "issue": issue,
                "evidence": f"Expires on {exp_date} ({days_until_expiry} days remaining)",
                "severity_hint": severity
            })

            # Issuer / Subject
            findings.append({
                "module_name": self.name,
                "issue": "Certificate issuer",
                "evidence": cert_obj.issuer.rfc4514_string(),
                "severity_hint": "info"
            })

            findings.append({
                "module_name": self.name,
                "issue": "Certificate subject",
                "evidence": cert_obj.subject.rfc4514_string(),
                "severity_hint": "info"
            })

            # Signature Algorithm Check
            sig_algo = cert_obj.signature_hash_algorithm.name.lower()
            if sig_algo in ["sha1", "md5"]:
                findings.append({
                    "module_name": self.name,
                    "issue": "Weak certificate signature algorithm",
                    "evidence": f"Signature algorithm: {sig_algo}",
                    "severity_hint": "high"
                })

            # SAN / Hostname validation
            try:
                san_ext = cert_obj.extensions.get_extension_for_class(
                    x509.SubjectAlternativeName
                )
                san_list = san_ext.value.get_values_for_type(x509.DNSName)

                host_matched = any(
                    host == name or
                    (name.startswith("*.") and host.endswith(name[1:]))
                    for name in san_list
                )

                if not host_matched:
                    findings.append({
                        "module_name": self.name,
                        "issue": "Certificate subject mismatch",
                        "evidence": f"Certificate does not match hostname {host}",
                        "severity_hint": "high"
                    })

            except Exception:
                pass

            # Public key strength
            public_key = cert_obj.public_key()

            if isinstance(public_key, rsa.RSAPublicKey):
                key_size = public_key.key_size
                if key_size < 2048:
                    findings.append({
                        "module_name": self.name,
                        "issue": "Weak RSA key size",
                        "evidence": f"RSA key size is {key_size} bits",
                        "severity_hint": "high"
                    })
                else:
                    findings.append({
                        "module_name": self.name,
                        "issue": "RSA key strength",
                        "evidence": f"RSA key size is {key_size} bits",
                        "severity_hint": "info"
                    })

        except Exception as e:
            findings.append({
                "module_name": self.name,
                "issue": "Certificate check failed",
                "evidence": str(e),
                "severity_hint": "medium"
            })

        return findings

    def _check_cipher(self, tls_sock):
        findings = []

        cipher = tls_sock.cipher()
        if not cipher:
            return findings

        cipher_name = cipher[0]
        tls_version = tls_sock.version()

        findings.append({
            "module_name": self.name,
            "issue": "Cipher suite",
            "evidence": f"Negotiated cipher: {cipher_name}",
            "severity_hint": "info"
        })
        
        # Weak algorithms
        weak_indicators = ["RC4", "3DES", "DES", "NULL", "MD5"]
        if any(w in cipher_name.upper() for w in weak_indicators):
            findings.append({
                "module_name": self.name,
                "issue": "Weak cipher detected",
                "evidence": f"{cipher_name} contains deprecated algorithm",
                "severity_hint": "high"
            })

        return findings

    def _probe_tls_versions(self, host, port, timeout):
        findings = []
        supported = []

        versions = {
            "TLSv1.0": ssl.TLSVersion.TLSv1,
            "TLSv1.1": ssl.TLSVersion.TLSv1_1,
            "TLSv1.2": ssl.TLSVersion.TLSv1_2,
            "TLSv1.3": ssl.TLSVersion.TLSv1_3,
        }

        for name, version in versions.items():
            try:
                context = ssl.create_default_context()
                context.minimum_version = version
                context.maximum_version = version
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE

                sock = socket.create_connection((host, port), timeout=timeout)
                tls_sock = context.wrap_socket(sock, server_hostname=host)

                if tls_sock.version():
                    supported.append(name)

                tls_sock.close()

            except Exception:
                continue

        findings.append({
            "module_name": self.name,
            "issue": "Supported TLS versions",
            "evidence": f"Supported: {', '.join(supported)}",
            "severity_hint": "info"
        })

        if "TLSv1.0" in supported or "TLSv1.1" in supported:
            findings.append({
                "module_name": self.name,
                "issue": "Deprecated TLS versions enabled",
                "evidence": "Server supports TLS 1.0 or TLS 1.1",
                "severity_hint": "high"
            })

        return findings
    
    def _check_forward_secrecy_support(self, host, port, timeout):
        findings = []

        try:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            context.set_ciphers("RSA")
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE

            sock = socket.create_connection((host, port), timeout=timeout)
            tls_sock = context.wrap_socket(sock, server_hostname=host)

            findings.append({
                "module_name": self.name,
                "issue": "Server supports non-Forward Secrecy ciphers",
                "evidence": "Handshake succeeded with static RSA cipher",
                "severity_hint": "medium"
            })

            tls_sock.close()

        except Exception:
            pass

        return findings