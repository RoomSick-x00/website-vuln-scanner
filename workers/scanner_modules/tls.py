from urllib.parse import urlparse
import socket
import ssl
from datetime import datetime, timezone

# Optional but recommended
try:
    from cryptography import x509
    from cryptography.x509.oid import NameOID
    from cryptography.hazmat.backends import default_backend
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

        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

        sock = None
        tls_sock = None

        try:
            print("Connecting to:", host)
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
            cert_findings = self._check_certificate(tls_sock, host)
            findings.extend(cert_findings)

            # Cipher + Forward Secrecy
            findings.extend(self._check_cipher(tls_sock))

            # TLS version matrix
            findings.extend(self._probe_tls_versions(host, port, timeout))

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
            # Get raw certificate (works even with CERT_NONE)
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

            cert_obj = x509.load_der_x509_certificate(cert_der, default_backend())

            exp_date = cert_obj.not_valid_after_utc
            now = datetime.now(timezone.utc)
            days_until_expiry = (exp_date - now).days

            if days_until_expiry < 0:
                severity = "high"
                issue = "Certificate expired"
            elif days_until_expiry < 30:
                severity = "medium"
                issue = "Certificate expiring soon"
            else:
                severity = "info"
                issue = "Certificate valid"

            findings.append({
                "module_name": self.name,
                "issue": issue,
                "evidence": f"Expires on {exp_date} ({days_until_expiry} days remaining)",
                "severity_hint": severity
            })

            issuer = cert_obj.issuer.rfc4514_string()
            findings.append({
                "module_name": self.name,
                "issue": "Certificate issuer",
                "evidence": issuer,
                "severity_hint": "info"
            })

            subject = cert_obj.subject.rfc4514_string()
            findings.append({
                "module_name": self.name,
                "issue": "Certificate subject",
                "evidence": subject,
                "severity_hint": "info"
            })


            try:
                san_extension = cert_obj.extensions.get_extension_for_class(
                    x509.SubjectAlternativeName
                )
                san_list = san_extension.value.get_values_for_type(x509.DNSName)

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

        if tls_version == "TLSv1.3":
            # TLS 1.3 always provides forward secrecy
            pass
        else:
            if "ECDHE" not in cipher_name and "DHE" not in cipher_name:
                findings.append({
                    "module_name": self.name,
                    "issue": "No Forward Secrecy",
                    "evidence": f"{cipher_name} does not support Forward Secrecy",
                    "severity_hint": "medium"
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
                context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
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