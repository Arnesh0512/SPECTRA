"""
crypto_recon.scanners.infrastructure.terraform_scanner
======================================================
Static scanner for Terraform (.tf) files.
Inspects cryptographic resource definitions including aws_kms_key,
tls_private_key, tls_self_signed_cert, and aws_acm_certificate.
"""

from dataclasses import dataclass, field
from pathlib import Path
import re
from typing import Any, Dict, List, Optional


@dataclass
class TerraformFinding:
    """Represents a discovered cryptographic resource in Terraform code."""
    source_domain: str = "infrastructure"
    infra_provider: str = "terraform"
    file_path: str = ""
    line_number: int = 0
    resource_type: str = ""
    resource_name: str = ""
    algorithm: str = "unknown"
    key_size: Optional[int] = None
    quantum_safe: bool = False
    shor_vulnerable: bool = True
    security_findings: List[Dict[str, str]] = field(default_factory=list)
    raw_metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "source_domain": self.source_domain,
            "infra_provider": self.infra_provider,
            "file_path": self.file_path,
            "line_number": self.line_number,
            "resource_type": self.resource_type,
            "resource_name": self.resource_name,
            "algorithm": self.algorithm,
            "key_size": self.key_size,
            "quantum_safe": self.quantum_safe,
            "shor_vulnerable": self.shor_vulnerable,
            "security_findings": self.security_findings,
            "raw_metadata": self.raw_metadata,
        }


# Regex to match Terraform resource blocks
RESOURCE_BLOCK_REGEX = re.compile(
    r'resource\s+["\'](?P<type>[a-zA-Z0-9_-]+)["\']\s+["\'](?P<name>[a-zA-Z0-9_-]+)["\']\s*\{',
    re.MULTILINE
)


class TerraformScanner:
    """Discovers cryptographic configurations within Terraform (.tf) definitions."""

    SUPPORTED_RESOURCES = {
        "aws_kms_key",
        "tls_private_key",
        "tls_self_signed_cert",
        "tls_locally_signed_cert",
        "aws_acm_certificate",
    }

    def scan_directory(self, target_dir: Path, excluded_dirs: Optional[List[str]] = None) -> List[TerraformFinding]:
        findings: List[TerraformFinding] = []
        excluded = set(excluded_dirs or [])

        for path in target_dir.rglob("*.tf"):
            if not path.is_file():
                continue
            if any(part in excluded for part in path.parts):
                continue
            findings.extend(self.scan_file(path))

        return findings

    def scan_file(self, file_path: Path) -> List[TerraformFinding]:
        try:
            with open(file_path, "r", encoding="utf-8", errors="replace") as f:
                content = f.read()
        except Exception:
            return []

        findings: List[TerraformFinding] = []
        lines = content.splitlines()

        for match in RESOURCE_BLOCK_REGEX.finditer(content):
            res_type = match.group("type")
            res_name = match.group("name")
            if res_type not in self.SUPPORTED_RESOURCES:
                continue

            # Calculate line number
            start_pos = match.start()
            line_no = content[:start_pos].count("\n") + 1

            # Extract resource body block
            block_body = self._extract_block_body(content, match.end())

            finding = self._evaluate_resource(
                file_path=file_path,
                line_no=line_no,
                res_type=res_type,
                res_name=res_name,
                body=block_body
            )
            if finding:
                findings.append(finding)

        return findings

    def _extract_block_body(self, content: str, start_index: int) -> str:
        """Extracts the balanced body between curly braces for the resource."""
        brace_depth = 1
        body_chars = []
        for char in content[start_index:]:
            if char == "{":
                brace_depth += 1
            elif char == "}":
                brace_depth -= 1
                if brace_depth == 0:
                    break
            body_chars.append(char)
        return "".join(body_chars)

    def _evaluate_resource(
        self,
        file_path: Path,
        line_no: int,
        res_type: str,
        res_name: str,
        body: str
    ) -> Optional[TerraformFinding]:
        sec_findings = []
        algo = "unknown"
        key_size: Optional[int] = None
        quantum_safe = False
        shor_vuln = True
        raw_meta: Dict[str, Any] = {}

        if res_type == "aws_kms_key":
            spec_match = re.search(r'customer_master_key_spec\s*=\s*["\']([^"\']+)["\']', body, re.IGNORECASE)
            key_spec = spec_match.group(1) if spec_match else "SYMMETRIC_DEFAULT"
            raw_meta["customer_master_key_spec"] = key_spec

            rot_match = re.search(r'enable_key_rotation\s*=\s*(true|false)', body, re.IGNORECASE)
            rot_enabled = rot_match.group(1).lower() == "true" if rot_match else False
            raw_meta["enable_key_rotation"] = rot_enabled

            if not rot_enabled and key_spec == "SYMMETRIC_DEFAULT":
                sec_findings.append({
                    "issue": "Terraform aws_kms_key defines enable_key_rotation as false",
                    "severity": "MEDIUM"
                })

            if "RSA" in key_spec:
                algo = "RSA"
                shor_vuln = True
                quantum_safe = False
                key_size = 2048 if "2048" in key_spec else (3072 if "3072" in key_spec else 4096)
            elif "ECC" in key_spec:
                algo = "ECC"
                shor_vuln = True
                quantum_safe = False
                key_size = 256
            else:
                algo = "AES-GCM"
                key_size = 256
                shor_vuln = False
                quantum_safe = True

        elif res_type == "tls_private_key":
            algo_match = re.search(r'algorithm\s*=\s*["\']([^"\']+)["\']', body, re.IGNORECASE)
            algo = algo_match.group(1).upper() if algo_match else "RSA"

            rsa_bits_match = re.search(r'rsa_bits\s*=\s*(\d+)', body, re.IGNORECASE)
            if algo == "RSA":
                key_size = int(rsa_bits_match.group(1)) if rsa_bits_match else 2048
                shor_vuln = True
                quantum_safe = False
                if key_size < 2048:
                    sec_findings.append({
                        "issue": f"Insecure RSA key size ({key_size} bits) configured in tls_private_key",
                        "severity": "HIGH"
                    })
            elif algo in ["ECDSA", "ED25519"]:
                shor_vuln = True
                quantum_safe = False
                key_size = 256

        elif res_type in ["tls_self_signed_cert", "tls_locally_signed_cert"]:
            algo = "X509-Certificate"
            shor_vuln = True
            quantum_safe = False
            validity_match = re.search(r'validity_period_hours\s*=\s*(\d+)', body, re.IGNORECASE)
            if validity_match:
                hours = int(validity_match.group(1))
                raw_meta["validity_period_hours"] = hours
                if hours > 8760 * 2:  # > 2 years
                    sec_findings.append({
                        "issue": f"Excessive certificate validity duration: {hours} hours (~{hours//8760} years)",
                        "severity": "LOW"
                    })

        elif res_type == "aws_acm_certificate":
            key_algo_match = re.search(r'key_algorithm\s*=\s*["\']([^"\']+)["\']', body, re.IGNORECASE)
            algo = key_algo_match.group(1) if key_algo_match else "RSA_2048"
            shor_vuln = True
            quantum_safe = False
            key_size = 2048 if "2048" in algo else (3072 if "3072" in algo else 4096)

        return TerraformFinding(
            source_domain="infrastructure",
            infra_provider="terraform",
            file_path=str(file_path.resolve()),
            line_number=line_no,
            resource_type=res_type,
            resource_name=res_name,
            algorithm=algo,
            key_size=key_size,
            quantum_safe=quantum_safe,
            shor_vulnerable=shor_vuln,
            security_findings=sec_findings,
            raw_metadata=raw_meta,
        )