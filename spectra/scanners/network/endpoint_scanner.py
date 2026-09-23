"""
spectra.scanners.network.endpoint_scanner
==============================================
Live network endpoint TLS handshake scanner.
Negotiates TLS connections against remote host:port targets to inspect negotiated
ciphers, protocol versions, server certificates, and Shor vulnerability.
"""

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
import socket
import ssl

from cryptography import x509
from cryptography.hazmat.backends import default_backend


@dataclass
class NetworkEndpointFinding:
    """Represents the cryptographic posture of a live network TLS endpoint."""
    source_domain: str = "network"
    target: str = ""
    port: int = 443
    tls_version: str = "unknown"
    cipher_suite: str = "unknown"
    key_exchange: str = "unknown"
    symmetric_cipher: str = "unknown"
    mac_algorithm: str = "unknown"
    cert_subject: str = ""
    cert_issuer: str = ""
    cert_expiration: Optional[str] = None
    days_to_expiration: Optional[int] = None
    cert_signature_algo: str = "unknown"
    cert_public_key_algo: str = "unknown"
    cert_key_size: Optional[int] = None
    quantum_safe: bool = False
    shor_vulnerable: bool = True
    security_findings: List[Dict[str, str]] = field(default_factory=list)
    raw_metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "source_domain": self.source_domain,
            "target": self.target,
            "port": self.port,
            "tls_version": self.tls_version,
            "cipher_suite": self.cipher_suite,
            "key_exchange": self.key_exchange,
            "symmetric_cipher": self.symmetric_cipher,
            "mac_algorithm": self.mac_algorithm,
            "cert_subject": self.cert_subject,
            "cert_issuer": self.cert_issuer,
            "cert_expiration": self.cert_expiration,
            "days_to_expiration": self.days_to_expiration,
            "cert_signature_algo": self.cert_signature_algo,
            "cert_public_key_algo": self.cert_public_key_algo,
            "cert_key_size": self.cert_key_size,
            "quantum_safe": self.quantum_safe,
            "shor_vulnerable": self.shor_vulnerable,
            "security_findings": self.security_findings,
            "raw_metadata": self.raw_metadata,
        }


class EndpointScanner:
    """Performs TLS handshakes to determine negotiated cryptographic parameters."""

    def __init__(self, timeout: int = 5):
        self.timeout = timeout

    def scan_endpoint(self, host: str, port: int = 443) -> Optional[NetworkEndpointFinding]:
        """Connects to host:port via TLS, extracts negotiated parameters and certificate chain."""
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

        try:
            with socket.create_connection((host, port), timeout=self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=host) as ssock:
                    tls_version = ssock.version() or "unknown"
                    cipher_info = ssock.cipher()  # (name, protocol_version, bits)
                    cipher_suite = cipher_info[0] if cipher_info else "unknown"

                    der_cert = ssock.getpeercert(binary_form=True)
                    if not der_cert:
                        return None

                    cert = x509.load_der_x509_certificate(der_cert, default_backend())
                    return self._evaluate_handshake(host, port, tls_version, cipher_suite, cert)
        except Exception:
            return None

    def _evaluate_handshake(
        self,
        host: str,
        port: int,
        tls_version: str,
        cipher_suite: str,
        cert: x509.Certificate
    ) -> NetworkEndpointFinding:
        sec_findings = []

        # 1. Protocol version checks
        if tls_version in ["SSLv2", "SSLv3", "TLSv1", "TLSv1.1"]:
            sec_findings.append({
                "issue": f"Deprecated and insecure protocol negotiated: {tls_version}",
                "severity": "CRITICAL"
            })

        # 2. Cipher suite evaluation
        kex = "unknown"
        if "ECDHE" in cipher_suite:
            kex = "ECDHE"
        elif "DHE" in cipher_suite:
            kex = "DHE"
        elif "RSA" in cipher_suite:
            kex = "RSA"
            sec_findings.append({
                "issue": "Static RSA key exchange used (lacks forward secrecy)",
                "severity": "HIGH"
            })

        if "CBC" in cipher_suite:
            sec_findings.append({
                "issue": "CBC mode cipher suite negotiated (susceptible to padding oracle attacks in TLS)",
                "severity": "MEDIUM"
            })

        # 3. Certificate parameters
        now = datetime.now(timezone.utc)
        not_after = cert.not_valid_after_utc
        days_left = (not_after - now).days

        if days_left < 0:
            sec_findings.append({
                "issue": f"Server certificate expired {abs(days_left)} day(s) ago",
                "severity": "CRITICAL"
            })
        elif days_left < 30:
            sec_findings.append({
                "issue": f"Server certificate expiring soon ({days_left} days remaining)",
                "severity": "MEDIUM"
            })

        sig_algo = cert.signature_hash_algorithm.name if cert.signature_hash_algorithm else "unknown"
        if sig_algo.lower() in ["md5", "sha1"]:
            sec_findings.append({
                "issue": f"Weak signature digest on server certificate: {sig_algo.upper()}",
                "severity": "HIGH"
            })

        pub_key = cert.public_key()
        key_algo = pub_key.__class__.__name__.replace("PublicKey", "").replace("_", "")
        key_size = getattr(pub_key, "key_size", None)

        if key_algo.upper() == "RSA" and key_size and key_size < 2048:
            sec_findings.append({
                "issue": f"Weak RSA certificate key size: {key_size} bits",
                "severity": "HIGH"
            })

        # Shor vulnerability check: Classical public key exchanges (ECDHE, RSA) are vulnerable
        shor_vuln = True
        quantum_safe = False
        if "KYBER" in cipher_suite.upper() or "ML-KEM" in cipher_suite.upper():
            quantum_safe = True
            shor_vuln = False

        return NetworkEndpointFinding(
            source_domain="network",
            target=host,
            port=port,
            tls_version=tls_version,
            cipher_suite=cipher_suite,
            key_exchange=kex,
            symmetric_cipher=cipher_suite,
            cert_subject=cert.subject.rfc4514_string(),
            cert_issuer=cert.issuer.rfc4514_string(),
            cert_expiration=not_after.isoformat(),
            days_to_expiration=days_left,
            cert_signature_algo=sig_algo.upper(),
            cert_public_key_algo=key_algo,
            cert_key_size=key_size,
            quantum_safe=quantum_safe,
            shor_vulnerable=shor_vuln,
            security_findings=sec_findings,
            raw_metadata={"serial_number": hex(cert.serial_number)}
        )