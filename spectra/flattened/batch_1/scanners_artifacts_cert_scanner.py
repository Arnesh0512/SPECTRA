"""
spectra.scanners.artifacts.cert_scanner
============================================
Discovers and inspects X.509 digital certificates and private key files on disk.
Evaluates signature algorithms, public key types, key lengths, expiration horizons,
and Shor quantum vulnerability.
"""

from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed25519, ed448, rsa, x25519, x448


@dataclass
class CertFinding:
    """Represents a discovered certificate or key artifact."""
    source_domain: str = "artifacts"
    artifact_type: str = "x509_certificate"  # x509_certificate, private_key
    file_path: str = ""
    subject: str = ""
    issuer: str = ""
    serial_number: str = ""
    not_valid_before: Optional[str] = None
    not_valid_after: Optional[str] = None
    days_to_expiration: Optional[int] = None
    signature_algorithm: str = "unknown"
    public_key_algorithm: str = "unknown"
    key_size: Optional[int] = None
    quantum_safe: bool = False
    shor_vulnerable: bool = True
    security_findings: List[Dict[str, str]] = field(default_factory=list)
    raw_metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "source_domain": self.source_domain,
            "artifact_type": self.artifact_type,
            "file_path": self.file_path,
            "subject": self.subject,
            "issuer": self.issuer,
            "serial_number": self.serial_number,
            "not_valid_before": self.not_valid_before,
            "not_valid_after": self.not_valid_after,
            "days_to_expiration": self.days_to_expiration,
            "signature_algorithm": self.signature_algorithm,
            "public_key_algorithm": self.public_key_algorithm,
            "key_size": self.key_size,
            "quantum_safe": self.quantum_safe,
            "shor_vulnerable": self.shor_vulnerable,
            "security_findings": self.security_findings,
            "raw_metadata": self.raw_metadata
        }


class CertScanner:
    """Scans directories for PEM/DER X.509 certificates and keys."""

    CERT_EXTENSIONS = {".pem", ".crt", ".cer", ".der", ".cert"}

    def scan_directory(self, target_dir: Path, excluded_dirs: Optional[List[str]] = None) -> List[CertFinding]:
        findings: List[CertFinding] = []
        excluded = set(excluded_dirs or [])

        for path in target_dir.rglob("*"):
            if not path.is_file():
                continue
            if any(part in excluded for part in path.parts):
                continue
            if path.suffix.lower() in self.CERT_EXTENSIONS:
                finding = self.scan_file(path)
                if finding:
                    findings.append(finding)

        return findings

    def scan_file(self, file_path: Path) -> Optional[CertFinding]:
        try:
            with open(file_path, "rb") as f:
                data = f.read()

            # Attempt PEM decode first, then DER fallback
            cert = None
            try:
                cert = x509.load_pem_x509_certificate(data, default_backend())
            except Exception:
                try:
                    cert = x509.load_der_x509_certificate(data, default_backend())
                except Exception:
                    return None

            return self._parse_x509_cert(file_path, cert)
        except Exception:
            return None

    def _parse_x509_cert(self, file_path: Path, cert: x509.Certificate) -> CertFinding:
        sec_findings = []
        now = datetime.now(timezone.utc)

        # Subject & Issuer
        subject_str = cert.subject.rfc4514_string()
        issuer_str = cert.issuer.rfc4514_string()

        # Dates & Expiration
        not_before = cert.not_valid_before_utc
        not_after = cert.not_valid_after_utc
        days_left = (not_after - now).days

        if days_left < 0:
            sec_findings.append({
                "issue": f"Certificate expired {abs(days_left)} day(s) ago",
                "severity": "CRITICAL"
            })
        elif days_left < 30:
            sec_findings.append({
                "issue": f"Certificate expiring soon ({days_left} days remaining)",
                "severity": "MEDIUM"
            })

        # Signature Algorithm check
        sig_algo = cert.signature_hash_algorithm.name if cert.signature_hash_algorithm else "unknown"
        if sig_algo.lower() in ["md5", "sha1"]:
            sec_findings.append({
                "issue": f"Cryptographically broken signature digest used: {sig_algo.upper()}",
                "severity": "HIGH"
            })

        # Public Key Extraction
        pub_key = cert.public_key()
        key_algo, key_size, shor_vuln = self._inspect_public_key(pub_key)

        if key_algo == "RSA" and key_size and key_size < 2048:
            sec_findings.append({
                "issue": f"Weak RSA key length ({key_size} bits); minimum recommended is 2048 bits",
                "severity": "HIGH"
            })

        return CertFinding(
            source_domain="artifacts",
            artifact_type="x509_certificate",
            file_path=str(file_path.resolve()),
            subject=subject_str,
            issuer=issuer_str,
            serial_number=hex(cert.serial_number),
            not_valid_before=not_before.isoformat(),
            not_valid_after=not_after.isoformat(),
            days_to_expiration=days_left,
            signature_algorithm=sig_algo.upper(),
            public_key_algorithm=key_algo,
            key_size=key_size,
            quantum_safe=not shor_vuln,
            shor_vulnerable=shor_vuln,
            security_findings=sec_findings,
            raw_metadata={"version": cert.version.name}
        )

    def _inspect_public_key(self, pub_key: Any) -> tuple[str, Optional[int], bool]:
        """Returns (algorithm_name, bit_length, is_shor_vulnerable)."""
        if isinstance(pub_key, rsa.RSAPublicKey):
            return "RSA", pub_key.key_size, True
        elif isinstance(pub_key, ec.EllipticCurvePublicKey):
            return f"ECC-{pub_key.curve.name}", pub_key.key_size, True
        elif isinstance(pub_key, dsa.DSAPublicKey):
            return "DSA", pub_key.key_size, True
        elif isinstance(pub_key, ed25519.Ed25519PublicKey):
            return "Ed25519", 256, True
        elif isinstance(pub_key, ed448.Ed448PublicKey):
            return "Ed448", 448, True
        elif isinstance(pub_key, x25519.X25519PublicKey):
            return "X25519", 256, True
        elif isinstance(pub_key, x448.X448PublicKey):
            return "X448", 448, True
        return "Unknown", None, True