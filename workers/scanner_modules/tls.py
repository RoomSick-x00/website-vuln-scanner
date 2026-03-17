from urllib.parse import urlparse
import socket
import ssl
from datetime import datetime, timezone

try:
    from cryptography import x509
    from cryptography.hazmat.primitives.asymmetric import rsa, ec
    CRYPTO_AVAILABLE = True
except ImportError:
    CRYPTO_AVAILABLE = False


# ---------------------------------------------------------------------------
# Finding helper — ensures every finding has a consistent shape
# ---------------------------------------------------------------------------

def _finding(issue: str, evidence: str, severity: str, remediation: str = "", score_penalty: int = 0) -> dict:
    """
    Canonical finding shape used across all scanner modules.

    severity:     "info" | "low" | "medium" | "high" | "critical"
    score_penalty: how many points this deducts from the site's total score (0–100 scale)
    remediation:  human-readable fix guidance shown in the report
    """
    return {
        "module_name": "tls",
        "issue": issue,
        "evidence": evidence,
        "severity": severity,
        "score_penalty": score_penalty,
        "remediation": remediation,
    }


# ---------------------------------------------------------------------------
# TLSScanner
# ---------------------------------------------------------------------------

class TLSScanner:
    name = "tls"

    def _try_legacy_tls(self, host: str, port: int, timeout: int):
        """
        Fallback connection allowing TLS 1.0+ — handles servers that only
        support deprecated protocol versions. TLS 1.0/1.1 are still present
        in OpenSSL unlike RC4 which may be compiled out entirely.
        """
        try:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            # Force legacy protocol negotiation (TLS 1.0) and lower OpenSSL security level.
            # This is needed on many OpenSSL 3.x builds where TLSv1.0/1.1 are disabled by policy.
            ctx.minimum_version = ssl.TLSVersion.TLSv1
            ctx.maximum_version = ssl.TLSVersion.TLSv1
            try:
                ctx.set_ciphers("ALL:@SECLEVEL=0")
            except Exception:
                pass
            # Best-effort: clear any "no TLSv1" flags if they exist in this Python/OpenSSL build.
            for opt_name in ("OP_NO_TLSv1", "OP_NO_TLSv1_1"):
                opt = getattr(ssl, opt_name, None)
                if isinstance(opt, int):
                    ctx.options &= ~opt

            sock = socket.create_connection((host, port), timeout=timeout)
            try:
                tls_sock = ctx.wrap_socket(sock, server_hostname=host)
            except Exception:
                sock.close()
                raise
            return True, tls_sock
        except Exception as e:
            return False, str(e)

    def scan(self, target: str, timeout: int = 10) -> list[dict]:
        findings = []

        parsed = urlparse(target)
        host = parsed.hostname
        port = parsed.port or 443

        if not host:
            findings.append(_finding(
                "Invalid target",
                f"Could not parse hostname from: {target}",
                "medium",
                "Ensure the URL is well-formed, e.g. https://example.com",
            ))
            return findings

        # ── Primary connection (CERT_NONE so we can always retrieve the cert) ──
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

        sock = tls_sock = None
        try:
            sock = socket.create_connection((host, port), timeout=timeout)
            tls_sock = context.wrap_socket(sock, server_hostname=host)

            findings.append(_finding(
                "TLS protocol negotiated",
                f"Negotiated protocol: {tls_sock.version()}",
                "info",
            ))

            findings.extend(self._check_certificate(tls_sock, host))
            findings.extend(self._check_cipher(tls_sock))

        except ssl.SSLError as e:
            # Before giving up, try with a lower minimum TLS version.
            # This handles servers that only support TLS 1.0 or 1.1 —
            # which are deprecated but still present in OpenSSL (unlike RC4).
            fallback_ok, fallback_result = self._try_legacy_tls(host, port, timeout)

            if fallback_ok:
                findings.append(_finding(
                    "TLS handshake failed with modern settings",
                    "Server does not support TLS 1.2 or higher -- modern clients will reject it.",
                    "critical",
                    "Upgrade your server to support TLS 1.2 and TLS 1.3.",
                    score_penalty=40,
                ))
                findings.append(_finding(
                    "TLS protocol negotiated (legacy)",
                    f"Negotiated protocol: {fallback_result.version()}",
                    "info",
                ))
                findings.extend(self._check_certificate(fallback_result, host))
                findings.extend(self._check_cipher(fallback_result))
                fallback_result.close()
                findings.extend(self._check_chain_trust(host, port, timeout))
                findings.extend(self._probe_tls_versions(host, port, timeout))
                findings.extend(self._check_forward_secrecy(host, port, timeout))
            else:
                findings.append(_finding(
                    "TLS handshake failed",
                    str(e),
                    "high",
                    "Ensure the server has a valid TLS certificate and supports TLS 1.2+.",
                    score_penalty=40,
                ))
            return findings

        except OSError as e:
            findings.append(_finding(
                "Connection failed",
                str(e),
                "medium",
                "Check that the host is reachable and port 443 is open.",
                score_penalty=20,
            ))
            return findings

        finally:
            if tls_sock:
                tls_sock.close()
            elif sock:
                sock.close()

        # ── Chain validation (separate connection WITH cert verification) ──
        findings.extend(self._check_chain_trust(host, port, timeout))

        # ── TLS version matrix + forward secrecy ──
        findings.extend(self._probe_tls_versions(host, port, timeout))
        findings.extend(self._check_forward_secrecy(host, port, timeout))

        return findings

    # -----------------------------------------------------------------------
    # Certificate checks
    # -----------------------------------------------------------------------

    def _check_certificate(self, tls_sock: ssl.SSLSocket, host: str) -> list[dict]:
        findings = []

        cert_der = tls_sock.getpeercert(binary_form=True)
        if not cert_der:
            findings.append(_finding(
                "Certificate not available",
                "Server did not present a certificate.",
                "high",
                "Configure the server to present a valid TLS certificate.",
                score_penalty=40,
            ))
            return findings

        if not CRYPTO_AVAILABLE:
            findings.append(_finding(
                "Cryptography library missing",
                "Install 'cryptography' (pip install cryptography) for full cert analysis.",
                "low",
            ))
            return findings

        try:
            cert = x509.load_der_x509_certificate(cert_der)
        except Exception as e:
            findings.append(_finding(
                "Certificate parse error",
                str(e),
                "medium",
                "The certificate could not be parsed — it may be malformed.",
                score_penalty=20,
            ))
            return findings

        # ── Expiry ──────────────────────────────────────────────────────────
        try:
            # not_valid_after_utc was added in cryptography 42.x; fall back gracefully
            exp_date = cert.not_valid_after_utc
        except AttributeError:
            exp_date = cert.not_valid_after.replace(tzinfo=timezone.utc)

        now = datetime.now(timezone.utc)
        days_left = (exp_date - now).days

        if days_left < 0:
            findings.append(_finding(
                "Certificate expired",
                f"Expired on {exp_date.date()} ({abs(days_left)} days ago)",
                "critical",
                "Renew your TLS certificate immediately. Use Let's Encrypt for free, auto-renewing certificates.",
                score_penalty=50,
            ))
        elif days_left < 14:
            findings.append(_finding(
                "Certificate expiring very soon",
                f"Expires on {exp_date.date()} ({days_left} days remaining)",
                "high",
                "Renew your certificate now. Set up auto-renewal (e.g. certbot renew) to avoid future expiry.",
                score_penalty=30,
            ))
        elif days_left < 30:
            findings.append(_finding(
                "Certificate expiring soon",
                f"Expires on {exp_date.date()} ({days_left} days remaining)",
                "medium",
                "Plan certificate renewal within the next two weeks.",
                score_penalty=10,
            ))
        else:
            findings.append(_finding(
                "Certificate valid",
                f"Expires on {exp_date.date()} ({days_left} days remaining)",
                "info",
            ))

        # ── Self-signed detection ────────────────────────────────────────────
        if cert.issuer == cert.subject:
            findings.append(_finding(
                "Self-signed certificate",
                f"Issuer matches subject: {cert.issuer.rfc4514_string()}",
                "high",
                "Replace with a certificate issued by a trusted CA (e.g. Let's Encrypt). "
                "Self-signed certs trigger browser warnings and break trust chains.",
                score_penalty=35,
            ))
        else:
            findings.append(_finding(
                "Certificate issuer",
                cert.issuer.rfc4514_string(),
                "info",
            ))

        # ── Signature algorithm ──────────────────────────────────────────────
        try:
            sig_algo = cert.signature_hash_algorithm.name.lower()
            if sig_algo in ("sha1", "md5"):
                findings.append(_finding(
                    "Weak signature algorithm",
                    f"Certificate signed with {sig_algo.upper()}",
                    "high",
                    f"Re-issue the certificate using SHA-256 or stronger. "
                    f"{sig_algo.upper()} is cryptographically broken.",
                    score_penalty=30,
                ))
        except Exception:
            pass  # Some certs (e.g. Ed25519) have no hash algorithm attribute

        # ── SAN / hostname validation ────────────────────────────────────────
        try:
            san_ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
            san_names = san_ext.value.get_values_for_type(x509.DNSName)

            def matches_san(h: str, san: str) -> bool:
                if san == h:
                    return True
                if san.startswith("*."):
                    # Must be exactly one label deeper — *.example.com matches sub.example.com
                    # but NOT sub.sub.example.com or example.com
                    suffix = san[1:]  # ".example.com"
                    return (
                        h.endswith(suffix)
                        and h.count(".") == san.count(".")
                    )
                return False

            if not any(matches_san(host, san) for san in san_names):
                findings.append(_finding(
                    "Hostname not in certificate SAN",
                    f"None of the SANs {san_names} match '{host}'",
                    "high",
                    "Re-issue the certificate and include the correct hostname in the "
                    "Subject Alternative Name (SAN) extension.",
                    score_penalty=35,
                ))
        except x509.ExtensionNotFound:
            findings.append(_finding(
                "No Subject Alternative Name extension",
                "Certificate has no SAN extension — modern browsers reject these.",
                "high",
                "Re-issue the certificate with a SAN extension listing the domain.",
                score_penalty=20,
            ))
        except Exception as e:
            findings.append(_finding(
                "SAN check error",
                str(e),
                "low",
            ))

        # ── Public key strength ──────────────────────────────────────────────
        pub = cert.public_key()

        if isinstance(pub, rsa.RSAPublicKey):
            key_size = pub.key_size
            if key_size < 2048:
                findings.append(_finding(
                    "Weak RSA key",
                    f"RSA key is {key_size} bits",
                    "high",
                    "Re-issue the certificate with at least a 2048-bit RSA key (4096-bit recommended).",
                    score_penalty=30,
                ))
            else:
                findings.append(_finding(
                    "RSA key strength",
                    f"RSA key is {key_size} bits",
                    "info",
                ))

        elif isinstance(pub, ec.EllipticCurvePublicKey):
            key_size = pub.key_size
            if key_size < 256:
                findings.append(_finding(
                    "Weak EC key",
                    f"EC key is {key_size} bits",
                    "high",
                    "Re-issue the certificate using P-256 (prime256v1) or stronger.",
                    score_penalty=30,
                ))
            else:
                findings.append(_finding(
                    "EC key strength",
                    f"EC key is {key_size} bits (curve: {pub.curve.name})",
                    "info",
                ))

        return findings

    # -----------------------------------------------------------------------
    # Chain trust validation (separate connection WITH verification)
    # -----------------------------------------------------------------------

    def _check_chain_trust(self, host: str, port: int, timeout: int) -> list[dict]:
        findings = []
        try:
            context = ssl.create_default_context()
            context.check_hostname = True
            context.verify_mode = ssl.CERT_REQUIRED

            sock = socket.create_connection((host, port), timeout=timeout)
            tls_sock = context.wrap_socket(sock, server_hostname=host)
            tls_sock.close()

            findings.append(_finding(
                "Certificate chain trusted",
                "Chain validates against system trust store.",
                "info",
            ))
        except ssl.SSLCertVerificationError as e:
            findings.append(_finding(
                "Certificate chain validation failed",
                str(e),
                "high",
                "Ensure your server sends the full certificate chain including all intermediate "
                "certificates. Use https://whatsmychaincert.com to diagnose.",
                score_penalty=35,
            ))
        except Exception:
            pass  # If we can't connect here, the primary scan already reported it

        return findings

    # -----------------------------------------------------------------------
    # Cipher suite check
    # -----------------------------------------------------------------------

    def _check_cipher(self, tls_sock: ssl.SSLSocket) -> list[dict]:
        findings = []

        cipher = tls_sock.cipher()
        if not cipher:
            return findings

        cipher_name = cipher[0]

        findings.append(_finding(
            "Negotiated cipher suite",
            cipher_name,
            "info",
        ))

        WEAK = ["RC4", "3DES", "DES", "NULL", "EXPORT", "MD5", "ANON"]
        matched = [w for w in WEAK if w in cipher_name.upper()]
        if matched:
            findings.append(_finding(
                "Weak cipher suite negotiated",
                f"{cipher_name} uses deprecated algorithm(s): {', '.join(matched)}",
                "high",
                "Disable weak ciphers in your web server config. For Nginx add: "
                "ssl_ciphers 'ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256'; "
                "For Apache: SSLCipherSuite HIGH:!aNULL:!MD5:!3DES",
                score_penalty=30,
            ))

        return findings

    # -----------------------------------------------------------------------
    # TLS version matrix
    # -----------------------------------------------------------------------

    def _probe_tls_versions(self, host: str, port: int, timeout: int) -> list[dict]:
        findings = []
        supported = []

        candidates = {
            "TLSv1.0": ssl.TLSVersion.TLSv1,
            "TLSv1.1": ssl.TLSVersion.TLSv1_1,
            "TLSv1.2": ssl.TLSVersion.TLSv1_2,
            "TLSv1.3": ssl.TLSVersion.TLSv1_3,
        }

        for label, version in candidates.items():
            try:
                # Use a legacy-capable context for TLS 1.0/1.1 probing on OpenSSL 3.x,
                # otherwise create_default_context() may block these by policy.
                if version in (ssl.TLSVersion.TLSv1, ssl.TLSVersion.TLSv1_1):
                    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                    ctx.check_hostname = False
                    ctx.verify_mode = ssl.CERT_NONE
                    ctx.minimum_version = version
                    ctx.maximum_version = version
                    try:
                        ctx.set_ciphers("ALL:@SECLEVEL=0")
                    except Exception:
                        pass
                    for opt_name in ("OP_NO_TLSv1", "OP_NO_TLSv1_1"):
                        opt = getattr(ssl, opt_name, None)
                        if isinstance(opt, int):
                            ctx.options &= ~opt
                else:
                    ctx = ssl.create_default_context()
                    ctx.minimum_version = version
                    ctx.maximum_version = version
                    ctx.check_hostname = False
                    ctx.verify_mode = ssl.CERT_NONE

                s = socket.create_connection((host, port), timeout=timeout)
                ts = ctx.wrap_socket(s, server_hostname=host)
                supported.append(label)
                ts.close()
            except Exception:
                continue

        if not supported:
            findings.append(_finding(
                "No TLS versions detected",
                "Could not negotiate any TLS version.",
                "high",
                "Ensure the server supports at least TLS 1.2.",
                score_penalty=40,
            ))
            return findings

        findings.append(_finding(
            "Supported TLS versions",
            ", ".join(supported),
            "info",
        ))

        deprecated = [v for v in ("TLSv1.0", "TLSv1.1") if v in supported]
        if deprecated:
            findings.append(_finding(
                "Deprecated TLS versions supported",
                f"Server accepts: {', '.join(deprecated)}",
                "high",
                "Disable TLS 1.0 and 1.1 in your server config. "
                "Nginx: ssl_protocols TLSv1.2 TLSv1.3; "
                "Apache: SSLProtocol -all +TLSv1.2 +TLSv1.3",
                score_penalty=25,
            ))

        if "TLSv1.2" not in supported and "TLSv1.3" not in supported:
            findings.append(_finding(
                "TLS 1.2 and 1.3 not supported",
                "Server does not support any modern TLS version.",
                "critical",
                "Enable TLS 1.2 and 1.3 immediately. They are required by PCI-DSS and most modern standards.",
                score_penalty=50,
            ))

        return findings

    # -----------------------------------------------------------------------
    # Forward secrecy
    # -----------------------------------------------------------------------

    def _check_forward_secrecy(self, host: str, port: int, timeout: int) -> list[dict]:
        """
        Test whether the server will accept a non-PFS cipher (static RSA key exchange).
        We explicitly force ECDHE/DHE ciphers on one connection and check what was
        negotiated, rather than relying on whether the RSA-only handshake succeeds
        (which OpenSSL often refuses to do on modern systems anyway).
        """
        findings = []

        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            # Force only ECDHE/DHE ciphers — if the server supports PFS this will succeed
            ctx.set_ciphers("ECDHE:DHE")

            s = socket.create_connection((host, port), timeout=timeout)
            ts = ctx.wrap_socket(s, server_hostname=host)
            cipher_name = ts.cipher()[0] if ts.cipher() else ""
            ts.close()

            if any(kex in cipher_name.upper() for kex in ("ECDHE", "DHE")):
                findings.append(_finding(
                    "Forward secrecy supported",
                    f"Server negotiated PFS cipher: {cipher_name}",
                    "info",
                ))
            else:
                findings.append(_finding(
                    "Forward secrecy may not be supported",
                    f"Negotiated cipher does not use ECDHE/DHE: {cipher_name}",
                    "medium",
                    "Configure your server to prefer ECDHE cipher suites to enable forward secrecy.",
                    score_penalty=15,
                ))

        except ssl.SSLError:
            # Handshake failed with ECDHE/DHE — server likely doesn't support PFS
            findings.append(_finding(
                "Forward secrecy not supported",
                "Server rejected all ECDHE/DHE cipher suites.",
                "medium",
                "Enable ECDHE cipher suites on your server. "
                "Nginx: ssl_ciphers 'ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:...';",
                score_penalty=15,
            ))
        except Exception:
            pass

        return findings