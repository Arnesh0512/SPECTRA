"""
spectra.scanners.artifacts.container_scanner
=================================================
Container image and Dockerfile cryptographic scanner.
Inspects container build definitions for embedded certificates, private keys,
cryptographic package installations, and environment-driven cipher controls.
"""

from dataclasses import dataclass, field
from pathlib import Path
import re
from typing import Any, Dict, List, Optional


@dataclass
class ContainerFinding:
    """Represents cryptographic evidence discovered within container manifests or Dockerfiles."""
    source_domain: str = "artifacts"
    artifact_type: str = "container_definition"
    file_path: str = ""
    line_number: int = 0
    finding_category: str = "embedded_crypto"  # embedded_crypto, base_image, env_crypto, copied_key
    details: str = ""
    algorithm: str = "unknown"
    quantum_safe: bool = False
    shor_vulnerable: bool = True
    security_findings: List[Dict[str, str]] = field(default_factory=list)
    raw_metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "source_domain": self.source_domain,
            "artifact_type": self.artifact_type,
            "file_path": self.file_path,
            "line_number": self.line_number,
            "finding_category": self.finding_category,
            "details": self.details,
            "algorithm": self.algorithm,
            "quantum_safe": self.quantum_safe,
            "shor_vulnerable": self.shor_vulnerable,
            "security_findings": self.security_findings,
            "raw_metadata": self.raw_metadata,
        }


# Regex to detect embedded PEM headers inside build scripts or Dockerfile RUN directives
EMBEDDED_KEY_REGEX = re.compile(
    r"-----BEGIN\s+(?:RSA\s+|EC\s+)?PRIVATE\s+KEY-----",
    re.MULTILINE
)

# Regex to detect COPY/ADD of private keys or certificates into image layers
COPY_KEY_REGEX = re.compile(
    r"^\s*(?:COPY|ADD)\s+.*\.(?:key|pem|p12|pfx|pkcs12)\b",
    re.IGNORECASE | re.MULTILINE
)

# Regex to detect environment variable crypto configurations
ENV_CRYPTO_REGEX = re.compile(
    r"^\s*ENV\s+(?P<var>SSL_CIPHER_SUITES|OPENSSL_CONF|NODE_OPTIONS|TLS_MIN_VERSION)\s*=?\s*(?P<val>[^\n]+)",
    re.IGNORECASE | re.MULTILINE
)


class ContainerScanner:
    """Discovers and evaluates cryptographic material embedded within container assets."""

    DOCKERFILE_NAMES = {"dockerfile", "containerfile"}

    def scan_directory(self, target_dir: Path, excluded_dirs: Optional[List[str]] = None) -> List[ContainerFinding]:
        findings: List[ContainerFinding] = []
        excluded = set(excluded_dirs or [])

        for path in target_dir.rglob("*"):
            if not path.is_file():
                continue
            if any(part in excluded for part in path.parts):
                continue
            if path.name.lower() in self.DOCKERFILE_NAMES or path.suffix.lower() in [".dockerfile", ".containerfile"]:
                findings.extend(self.scan_file(path))

        return findings

    def scan_file(self, file_path: Path) -> List[ContainerFinding]:
        try:
            with open(file_path, "r", encoding="utf-8", errors="replace") as f:
                content = f.read()
        except Exception:
            return []

        findings: List[ContainerFinding] = []

        # 1. Inspect for embedded private key blocks
        for match in EMBEDDED_KEY_REGEX.finditer(content):
            line_no = content[:match.start()].count("\n") + 1
            findings.append(ContainerFinding(
                source_domain="artifacts",
                artifact_type="container_definition",
                file_path=str(file_path.resolve()),
                line_number=line_no,
                finding_category="embedded_crypto",
                details="Hardcoded private key block detected directly inside Dockerfile",
                algorithm="RSA/ECC",
                quantum_safe=False,
                shor_vulnerable=True,
                security_findings=[{
                    "issue": "Private key material is baked into container image layers",
                    "severity": "CRITICAL"
                }],
                raw_metadata={"directive": "RUN/EMBEDDED"}
            ))

        # 2. Inspect COPY/ADD directives copying sensitive key files
        for match in COPY_KEY_REGEX.finditer(content):
            line_no = content[:match.start()].count("\n") + 1
            matched_line = match.group(0).strip()
            findings.append(ContainerFinding(
                source_domain="artifacts",
                artifact_type="container_definition",
                file_path=str(file_path.resolve()),
                line_number=line_no,
                finding_category="copied_key",
                details=f"Copying private key artifact into image: '{matched_line}'",
                algorithm="Private-Key",
                quantum_safe=False,
                shor_vulnerable=True,
                security_findings=[{
                    "issue": "Sensitive private key files copied into container filesystem layer",
                    "severity": "HIGH"
                }],
                raw_metadata={"matched_instruction": matched_line}
            ))

        # 3. Inspect ENV variables configuring TLS or OpenSSL
        for match in ENV_CRYPTO_REGEX.finditer(content):
            line_no = content[:match.start()].count("\n") + 1
            var_name = match.group("var")
            var_val = match.group("val").strip()

            sec_findings = []
            if "legacy" in var_val.lower() or "tlsv1" in var_val.lower():
                sec_findings.append({
                    "issue": f"Container environment sets legacy/weak TLS configuration: {var_name}={var_val}",
                    "severity": "HIGH"
                })

            findings.append(ContainerFinding(
                source_domain="artifacts",
                artifact_type="container_definition",
                file_path=str(file_path.resolve()),
                line_number=line_no,
                finding_category="env_crypto",
                details=f"Cryptographic environment variable set: {var_name}={var_val}",
                algorithm="Configuration",
                quantum_safe=False,
                shor_vulnerable=False,
                security_findings=sec_findings,
                raw_metadata={"env_var": var_name, "env_val": var_val}
            ))

        return findings