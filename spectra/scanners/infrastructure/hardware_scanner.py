"""
spectra.scanners.infrastructure.hardware_scanner
=====================================================
Discovers and audits hardware-level cryptographic assets and accelerators
cross-platform (Linux, Windows, macOS).
Loaded via rules/infra_patterns.yaml.
"""

from dataclasses import dataclass, field
from pathlib import Path
import platform
import re
import subprocess
from typing import Any, Dict, List, Optional
import yaml


@dataclass
class HardwareFinding:
    """Represents a discovered hardware cryptographic device or capability."""
    source_domain: str = "infrastructure"
    infra_provider: str = "hardware"
    device_type: str = "unknown"
    device_name: str = ""
    status: str = "active"
    algorithm: str = "hardware_crypto"
    quantum_safe: bool = False
    shor_vulnerable: bool = True
    security_findings: List[Dict[str, str]] = field(default_factory=list)
    raw_metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "source_domain": self.source_domain,
            "infra_provider": self.infra_provider,
            "device_type": self.device_type,
            "device_name": self.device_name,
            "status": self.status,
            "algorithm": self.algorithm,
            "quantum_safe": self.quantum_safe,
            "shor_vulnerable": self.shor_vulnerable,
            "security_findings": self.security_findings,
            "raw_metadata": self.raw_metadata,
        }


class HardwareScanner:
    """Probes host environment for hardware security modules across Linux, Windows, and macOS[cite: 35]."""

    def __init__(self, rules_file: Optional[Path] = None):
        if rules_file is None:
            rules_file = Path(__file__).parent / "rules" / "infra_patterns.yaml"
        self.rules = self._load_rules(rules_file)
        self.pkcs11_libs = self.rules.get("pkcs11_libraries", [
            "/usr/lib/softhsm/libsofthsm2.so",
            "/opt/cloudhsm/lib/libcloudhsm_pkcs11.so",
            "C:\\Program Files\\SoftHSM2\\lib\\softhsm2.dll"
        ])
        self.cpu_flags = self.rules.get("cpu_crypto_flags", ["aes", "sha_ni", "sha1", "sha2"])

    def _load_rules(self, path: Path) -> Dict[str, Any]:
        if not path.is_file():
            return {}
        try:
            with open(path, "r", encoding="utf-8") as f:
                return yaml.safe_load(f) or {}
        except Exception:
            return {}

    def scan(self) -> List[HardwareFinding]:
        """Runs cross-platform hardware audit checks across TPM, HSM libraries, and CPU crypto instructions[cite: 35]."""
        findings: List[HardwareFinding] = []
        findings.extend(self._scan_tpm())
        findings.extend(self._scan_pkcs11_hsms())
        findings.extend(self._scan_cpu_crypto_capabilities())
        return findings

    def _scan_tpm(self) -> List[HardwareFinding]:
        findings: List[HardwareFinding] = []
        system = platform.system()

        # 1. Linux TPM check[cite: 35]
        if system == "Linux":
            tpm_class_path = Path("/sys/class/tpm")
            if tpm_class_path.exists():
                for dev in tpm_class_path.glob("tpm*"):
                    tpm_version = "TPM 2.0"
                    desc_path = dev / "device/description"
                    if desc_path.exists():
                        try:
                            desc = desc_path.read_text(encoding="utf-8").strip()
                            if "1.2" in desc:
                                tpm_version = "TPM 1.2"
                        except Exception:
                            pass

                    sec_findings = []
                    if tpm_version == "TPM 1.2":
                        sec_findings.append({
                            "issue": "Legacy TPM 1.2 hardware detected (relies on deprecated SHA-1)",
                            "severity": "HIGH"
                        })

                    findings.append(HardwareFinding(
                        device_type="tpm",
                        device_name=f"{dev.name} ({tpm_version})",
                        status="present",
                        algorithm="RSA-2048 / ECC-NIST-P256",
                        quantum_safe=False,
                        shor_vulnerable=True,
                        security_findings=sec_findings,
                        raw_metadata={"sysfs_path": str(dev), "version": tpm_version}
                    ))
            elif Path("/dev/tpmrm0").exists():
                findings.append(HardwareFinding(
                    device_type="tpm",
                    device_name="TPM 2.0 Resource Manager (/dev/tpmrm0)",
                    status="present",
                    algorithm="RSA / ECC",
                    quantum_safe=False,
                    shor_vulnerable=True,
                    security_findings=[],
                    raw_metadata={"dev_path": "/dev/tpmrm0"}
                ))

        # 2. Windows TPM check via PowerShell[cite: 35]
        elif system == "Windows":
            try:
                cmd = ["powershell", "-Command", "Get-Tpm | Select-Object TpmPresent, TpmReady"]
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
                if result.returncode == 0 and "True" in result.stdout:
                    findings.append(HardwareFinding(
                        device_type="tpm",
                        device_name="Trusted Platform Module (TPM 2.0 Windows)",
                        status="present",
                        algorithm="RSA / ECC",
                        quantum_safe=False,
                        shor_vulnerable=True,
                        security_findings=[],
                        raw_metadata={"platform": "Windows WMI/PowerShell"}
                    ))
            except Exception:
                pass

        return findings

    def _scan_pkcs11_hsms(self) -> List[HardwareFinding]:
        findings: List[HardwareFinding] = []
        for lib_path_str in self.pkcs11_libs:
            lib_path = Path(lib_path_str)
            if lib_path.exists():
                provider_name = "PKCS#11 Module"
                lower_str = lib_path_str.lower()
                if "cloudhsm" in lower_str:
                    provider_name = "AWS CloudHSM"
                elif "softhsm" in lower_str:
                    provider_name = "SoftHSM2"
                elif "opensc" in lower_str or "ykcs11" in lower_str:
                    provider_name = "SmartCard / HSM Token"

                findings.append(HardwareFinding(
                    device_type="hsm",
                    device_name=f"{provider_name} ({lib_path.name})",
                    status="library_installed",
                    algorithm="Hardware-Protected Keys",
                    quantum_safe=False,
                    shor_vulnerable=True,
                    security_findings=[],
                    raw_metadata={"module_path": str(lib_path)}
                ))

        return findings

    def _scan_cpu_crypto_capabilities(self) -> List[HardwareFinding]:
        findings: List[HardwareFinding] = []
        cpu_features: List[str] = []
        system = platform.system()

        # 1. Linux CPU info check[cite: 35]
        if system == "Linux" and Path("/proc/cpuinfo").exists():
            try:
                content = Path("/proc/cpuinfo").read_text(encoding="utf-8", errors="ignore")
                flags_match = re.search(r"^(?:flags|Features)\s*:\s*(.+)$", content, re.MULTILINE)
                if flags_match:
                    raw_flags = flags_match.group(1).split()
                    for target_flag in self.cpu_flags:
                        if target_flag in raw_flags:
                            cpu_features.append(target_flag)
            except Exception:
                pass

        # 2. Windows CPU info check[cite: 35]
        elif system == "Windows":
            processor_arch = platform.machine()
            if processor_arch in ["AMD64", "x86_64", "ARM64"]:
                cpu_features.extend(["aes", "sha2"])

        # 3. macOS CPU info check[cite: 35]
        elif system == "Darwin":
            try:
                result = subprocess.run(["sysctl", "-n", "machdep.cpu.features"], capture_output=True, text=True, timeout=3)
                if result.returncode == 0:
                    features_lower = result.stdout.lower()
                    if "aes" in features_lower:
                        cpu_features.append("aes")
            except Exception:
                pass
            if platform.machine() == "arm64":
                cpu_features.extend(["aes", "sha2"])

        if cpu_features:
            findings.append(HardwareFinding(
                device_type="cpu_accelerator",
                device_name=f"CPU Cryptographic Extensions ({platform.processor() or platform.machine()})",
                status="active",
                algorithm="Hardware-Accelerated AES / SHA",
                quantum_safe=True,
                shor_vulnerable=False,
                security_findings=[],
                raw_metadata={"features": list(set(cpu_features))}
            ))

        return findings