"""
spectra.scanners.infrastructure.gcp_scanner
================================================
Audits Google Cloud Platform (GCP) Cloud KMS cryptographic assets.
Discovers and inspects GCP Cloud KMS keyrings, crypto keys, and primary versions
for key algorithms, key lengths, protection levels, and Shor vulnerability.
"""

from dataclasses import dataclass, field
import json
import os
from pathlib import Path
import shutil
import subprocess
from typing import Any, Dict, List, Optional


@dataclass
class GCPFinding:
    """Represents a discovered GCP Cloud KMS cryptographic asset."""
    source_domain: str = "infrastructure"
    infra_provider: str = "gcp"
    service: str = "cloud_kms"
    project_id: str = ""
    location: str = "global"
    key_ring: str = ""
    resource_id: str = ""
    resource_arn: str = ""
    algorithm: str = "unknown"
    key_spec: str = "unknown"
    key_size: Optional[int] = None
    quantum_safe: bool = False
    shor_vulnerable: bool = True
    security_findings: List[Dict[str, str]] = field(default_factory=list)
    raw_metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "source_domain": self.source_domain,
            "infra_provider": self.infra_provider,
            "service": self.service,
            "project_id": self.project_id,
            "location": self.location,
            "key_ring": self.key_ring,
            "resource_id": self.resource_id,
            "resource_arn": self.resource_arn,
            "algorithm": self.algorithm,
            "key_spec": self.key_spec,
            "key_size": self.key_size,
            "quantum_safe": self.quantum_safe,
            "shor_vulnerable": self.shor_vulnerable,
            "security_findings": self.security_findings,
            "raw_metadata": self.raw_metadata,
        }


class GCPScanner:
    """Discovers cryptographic configurations across GCP Cloud KMS keyrings and keys."""

    def __init__(self, project_id: Optional[str] = None, locations: Optional[List[str]] = None):
        self.project_id = project_id
        self.locations = locations or ["global"]
        self._gcloud_bin: Optional[str] = None

    def _resolve_gcloud(self) -> Optional[str]:
        if self._gcloud_bin:
            return self._gcloud_bin

        # 1. System PATH
        bin_path = shutil.which("gcloud")
        if bin_path:
            self._gcloud_bin = bin_path
            return bin_path

        # 2. LocalAppData standard installation path on Windows
        local_app_data = os.environ.get("LOCALAPPDATA", "")
        if local_app_data:
            candidate = Path(local_app_data) / "Google" / "Cloud SDK" / "google-cloud-sdk" / "bin" / "gcloud.cmd"
            if candidate.exists():
                self._gcloud_bin = str(candidate)
                return str(candidate)

        # 3. Program Files candidate paths
        for p in [r"C:\Program Files\Google\Cloud SDK\google-cloud-sdk\bin\gcloud.cmd",
                  r"C:\Program Files (x86)\Google\Cloud SDK\google-cloud-sdk\bin\gcloud.cmd"]:
            if Path(p).exists():
                self._gcloud_bin = p
                return p

        return None

    def is_available(self) -> bool:
        """Returns True if gcloud CLI or GCP credentials exist."""
        has_cli = self._resolve_gcloud() is not None
        has_adc = (Path(os.environ.get("APPDATA", "")) / "gcloud" / "application_default_credentials.json").exists()
        return has_cli or has_adc

    def _get_active_project(self) -> Optional[str]:
        if self.project_id:
            return self.project_id
        env_proj = os.environ.get("GOOGLE_CLOUD_PROJECT") or os.environ.get("GCP_PROJECT")
        if env_proj:
            return env_proj

        gcloud = self._resolve_gcloud()
        if gcloud:
            try:
                res = subprocess.run(
                    [gcloud, "config", "get-value", "project"],
                    capture_output=True,
                    text=True,
                    timeout=5,
                    shell=True if os.name == "nt" else False,
                )
                if res.returncode == 0 and res.stdout.strip():
                    proj = res.stdout.strip()
                    if proj != "(unset)":
                        return proj
            except Exception:
                pass
        return None

    def scan(self) -> List[GCPFinding]:
        """Discovers KMS KeyRings and inspects CryptoKeys across configured locations."""
        gcloud = self._resolve_gcloud()
        if not gcloud:
            return []

        project = self._get_active_project()
        findings: List[GCPFinding] = []

        for loc in self.locations:
            try:
                # 1. List KeyRings in location
                cmd = [gcloud, "kms", "keyrings", "list", f"--location={loc}", "--format=json"]
                if project:
                    cmd.append(f"--project={project}")

                res = subprocess.run(cmd, capture_output=True, text=True, timeout=10, shell=True if os.name == "nt" else False)
                if res.returncode != 0:
                    continue

                try:
                    keyrings = json.loads(res.stdout or "[]")
                except json.JSONDecodeError:
                    keyrings = []

                for kr in keyrings:
                    kr_name = kr.get("name", "")
                    # Extract ring ID from "projects/.../locations/.../keyRings/nexis-keyring"
                    kr_id = kr_name.split("/")[-1] if "/" in kr_name else kr_name

                    # 2. List CryptoKeys in KeyRing
                    k_cmd = [gcloud, "kms", "keys", "list", f"--location={loc}", f"--keyring={kr_id}", "--format=json"]
                    if project:
                        k_cmd.append(f"--project={project}")

                    k_res = subprocess.run(k_cmd, capture_output=True, text=True, timeout=10, shell=True if os.name == "nt" else False)
                    if k_res.returncode != 0:
                        continue

                    try:
                        keys = json.loads(k_res.stdout or "[]")
                    except json.JSONDecodeError:
                        keys = []

                    for k in keys:
                        finding = self._evaluate_crypto_key(k, project or "", loc, kr_id)
                        if finding:
                            findings.append(finding)

            except Exception:
                continue

        return findings

    def _evaluate_crypto_key(self, k: Dict[str, Any], project: str, location: str, keyring: str) -> Optional[GCPFinding]:
        full_name = k.get("name", "")
        key_id = full_name.split("/")[-1] if "/" in full_name else full_name
        purpose = k.get("purpose", "")

        primary = k.get("primary", {})
        version_tmpl = k.get("versionTemplate", {})
        spec = primary.get("algorithm") or version_tmpl.get("algorithm", "GOOGLE_SYMMETRIC_ENCRYPTION")
        prot_level = primary.get("protectionLevel") or version_tmpl.get("protectionLevel", "SOFTWARE")

        algo = "AES-GCM"
        key_size = 256
        shor_vuln = False
        quantum_safe = True
        sec_findings: List[Dict[str, str]] = []

        spec_upper = spec.upper()
        if "RSA" in spec_upper:
            algo = "RSA"
            shor_vuln = True
            quantum_safe = False
            if "2048" in spec_upper:
                key_size = 2048
            elif "3072" in spec_upper:
                key_size = 3072
            elif "4096" in spec_upper:
                key_size = 4096
        elif "EC_" in spec_upper or "ECDSA" in spec_upper:
            algo = "ECC"
            shor_vuln = True
            quantum_safe = False
            if "P256" in spec_upper:
                key_size = 256
            elif "P384" in spec_upper:
                key_size = 384
            else:
                key_size = 256
        elif "SYMMETRIC" in spec_upper:
            algo = "AES-GCM"
            key_size = 256
            quantum_safe = True
            shor_vuln = False

        # Rotation period check
        rotation_period = k.get("rotationPeriod")
        if not rotation_period and "SYMMETRIC" in spec_upper:
            sec_findings.append({
                "issue": "Automatic rotation period is not configured on GCP KMS key",
                "severity": "MEDIUM",
            })

        return GCPFinding(
            source_domain="infrastructure",
            infra_provider="gcp",
            service="cloud_kms",
            project_id=project,
            location=location,
            key_ring=keyring,
            resource_id=key_id,
            resource_arn=full_name,
            algorithm=algo,
            key_spec=spec,
            key_size=key_size,
            quantum_safe=quantum_safe,
            shor_vulnerable=shor_vuln,
            security_findings=sec_findings,
            raw_metadata={
                "purpose": purpose,
                "protection_level": prot_level,
                "create_time": k.get("createTime", ""),
                "primary_state": primary.get("state", "ENABLED"),
            },
        )
