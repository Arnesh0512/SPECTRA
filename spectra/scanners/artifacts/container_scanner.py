"""
spectra.scanners.artifacts.container_scanner
=================================================
Container image and Dockerfile cryptographic scanner.
Inspecting container build definitions via rules/container_patterns.yaml.
"""

from dataclasses import dataclass, field
from pathlib import Path
import re
from typing import Any, Callable, Dict, List, Optional
import yaml


@dataclass
class ContainerFinding:
    """Represents cryptographic evidence discovered within container manifests or Dockerfiles."""
    source_domain: str = "artifacts"
    artifact_type: str = "container_definition"
    file_path: str = ""
    line_number: int = 0
    finding_category: str = "embedded_crypto"
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


class ContainerScanner:
    """Discovers and evaluates cryptographic material embedded within container assets using rules/container_patterns.yaml."""

    def __init__(self, rules_file: Optional[Path] = None):
        if rules_file is None:
            rules_file = Path(__file__).parent / "rules" / "container_patterns.yaml"
        self.rules = self._load_rules(rules_file)
        
        self.dockerfile_names = set(self.rules.get("dockerfile_names", ["dockerfile", "containerfile"]))
        self.dockerfile_extensions = set(self.rules.get("dockerfile_extensions", [".dockerfile", ".containerfile"]))

        # Compile regex patterns from rules
        key_pats = self.rules.get("embedded_key_patterns", [r"----[-]?BEGIN\s+(?:RSA\s+|EC\s+)?PRIVATE\s+KEY----[-]?"])
        self.embedded_key_regex = re.compile("|".join(key_pats), re.MULTILINE)

        copy_pats = self.rules.get("copy_key_patterns", [r"^\s*(?:COPY|ADD)\s+.*\.(?:key|pem|p12|pfx|pkcs12)\b"])
        self.copy_key_regex = re.compile("|".join(copy_pats), re.IGNORECASE | re.MULTILINE)

        env_pats = self.rules.get("env_crypto_patterns", [r"^\s*ENV\s+(?P<var>SSL_CIPHER_SUITES|OPENSSL_CONF|NODE_OPTIONS|TLS_MIN_VERSION)\s*=?\s*(?P<val>[^\n]+)"])
        self.env_crypto_regex = re.compile("|".join(env_pats), re.IGNORECASE | re.MULTILINE)

    def _load_rules(self, path: Path) -> Dict[str, Any]:
        if not path.is_file():
            return {}
        try:
            with open(path, "r", encoding="utf-8") as f:
                return yaml.safe_load(f) or {}
        except Exception:
            return {}

    def scan_directory(
        self,
        target_dir: Path,
        excluded_dirs: Optional[List[str]] = None,
        progress_callback: Optional[Callable] = None,
    ) -> List[ContainerFinding]:
        findings: List[ContainerFinding] = []
        excluded = set(excluded_dirs or [])

        container_files: List[Path] = []
        for path in target_dir.rglob("*"):
            if not path.is_file():
                continue
            if any(part in excluded for part in path.parts):
                continue
            if path.name.lower() in self.dockerfile_names or path.suffix.lower() in self.dockerfile_extensions:
                container_files.append(path)

        total_cnt = len(container_files)
        for idx, path in enumerate(container_files, start=1):
            if progress_callback and total_cnt > 0:
                pct = 58.0 + (idx / total_cnt) * 4.0
                desc = f"Domain 2/4: Auditing Container ({idx}/{total_cnt}) {path.name}"
                try:
                    rel_loc = str(path.relative_to(target_dir)).replace("\\", "/")
                except Exception:
                    rel_loc = str(path).replace("\\", "/")
                progress_callback(
                    desc,
                    pct,
                    item_info={
                        "seq": f"{idx}/{total_cnt}",
                        "type": "container",
                        "filename": path.name,
                        "location": rel_loc,
                    }
                )
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
        for match in self.embedded_key_regex.finditer(content):
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
        for match in self.copy_key_regex.finditer(content):
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
        for match in self.env_crypto_regex.finditer(content):
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