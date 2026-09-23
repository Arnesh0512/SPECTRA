"""
spectra.scanners.infrastructure.hardware_scanner
=====================================================
Discovers and audits hardware-level cryptographic assets and accelerators:
Hardware Security Modules (HSM / PKCS#11), Trusted Platform Modules (TPM),
and CPU instruction set extensions (AES-NI, SHA-NI, ARM Cryptography Extensions).
"""

from dataclasses import dataclass, field
from pathlib import Path
import platform
import re
from typing import Any, Dict, List, Optional

from spectra.utils.shell import command_exists, run_command


@dataclass
class HardwareFinding:
    """Represents a discovered hardware cryptographic device or capability."""
    source_domain: str = "infrastructure"
    infra_provider: str = "hardware"
    device_type: str = "unknown"  # tpm, hsm, cpu_accelerator
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


# Standard paths for PKCS#11 shared libraries across Linux / macOS distributions
KNOWN_PKCS11_LIBS = [
    "/usr/lib/softhsm/libsofthsm2.so",
    "/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so",
    "/usr/local/lib/softhsm/libsofthsm2.so",
    "/opt/cloudhsm/lib/libcloudhsm_pkcs11.so",
    "/usr/lib/x86_64-linux-gnu/opensc-pkcs11.so",
    "/usr/lib/opensc-pkcs11.so",
    "/usr/local/lib/opensc-pkcs11.so",
    "/usr/lib/libykcs11.so",  # YubiKey PKCS#11
]


class HardwareScanner:
    """Probes host environment for hardware security modules, TPMs, and CPU acceleration."""

    def scan(self) -> List[HardwareFinding]:
        """Runs hardware audit checks across TPM, HSM libraries, and CPU crypto instructions."""
        findings: List[HardwareFinding] = []
        findings.extend(self._scan_tpm())
        findings.extend(self._scan_pkcs11_hsms())
        findings.extend(self._scan_cpu_crypto_capabilities())
        return findings

    def _scan_tpm(self) -> List[HardwareFinding]:
        findings: List[HardwareFinding] = []
        tpm_class_path = Path("/sys/class/tpm")

        if tpm_class_path.exists():
            devices = list(tpm_class_path.glob("tpm*"))
            for dev in devices:
                dev_name = dev.name
                tpm_version = "TPM 2.0"
                # Check description/version if exposed by sysfs
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
                    source_domain="infrastructure",
                    infra_provider="hardware",
                    device_type="tpm",
                    device_name=f"{dev_name} ({tpm_version})",
                    status="present",
                    algorithm="RSA-2048 / ECC-NIST-P256",
                    quantum_safe=False,
                    shor_vulnerable=True,
                    security_findings=sec_findings,
                    raw_metadata={"sysfs_path": str(dev), "version": tpm_version}
                ))

        # Check /dev/tpmrm0 (TPM 2.0 Resource Manager device node)
        elif Path("/dev/tpmrm0").exists():
            findings.append(HardwareFinding(
                source_domain="infrastructure",
                infra_provider="hardware",
                device_type="tpm",
                device_name="TPM 2.0 Resource Manager (/dev/tpmrm0)",
                status="present",
                algorithm="RSA / ECC",
                quantum_safe=False,
                shor_vulnerable=True,
                security_findings=[],
                raw_metadata={"dev_path": "/dev/tpmrm0"}
            ))

        return findings

    def _scan_pkcs11_hsms(self) -> List[HardwareFinding]:
        findings: List[HardwareFinding] = []

        for lib_path_str in KNOWN_PKCS11_LIBS:
            lib_path = Path(lib_path_str)
            if lib_path.exists():
                provider_name = "PKCS#11 Module"
                if "cloudhsm" in lib_path_str.lower():
                    provider_name = "AWS CloudHSM"
                elif "softhsm" in lib_path_str.lower():
                    provider_name = "SoftHSM2"
                elif "opensc" in lib_path_str.lower():
                    provider_name = "OpenSC SmartCard / HSM"
                elif "ykcs11" in lib_path_str.lower():
                    provider_name = "YubiKey PKCS#11"

                findings.append(HardwareFinding(
                    source_domain="infrastructure",
                    infra_provider="hardware",
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

        if system == "Linux" and Path("/proc/cpuinfo").exists():
            try:
                with open("/proc/cpuinfo", "r", encoding="utf-8", errors="ignore") as f:
                    content = f.read()
                # Find flags / Features line
                flags_match = re.search(r"^(?:flags|Features)\s*:\s*(.+)$", content, re.MULTILINE)
                if flags_match:
                    raw_flags = flags_match.group(1).split()
                    for target_flag in ["aes", "sha_ni", "sha1", "sha2", "pmull", "avx512f"]:
                        if target_flag in raw_flags:
                            cpu_features.append(target_flag)
            except Exception:
                pass

        elif system == "Darwin" and command_exists("sysctl"):
            code, stdout, _ = run_command(["sysctl", "-a"])
            if code == 0:
                for line in stdout.splitlines():
                    if "hw.optional.arm.FEAT_AES" in line and ": 1" in line:
                        cpu_features.append("arm_feat_aes")
                    elif "hw.optional.arm.FEAT_SHA256" in line and ": 1" in line:
                        cpu_features.append("arm_feat_sha256")
                    elif "hw.optional.avx512" in line and ": 1" in line:
                        cpu_features.append("avx512")

        if cpu_features:
            findings.append(HardwareFinding(
                source_domain="infrastructure",
                infra_provider="hardware",
                device_type="cpu_accelerator",
                device_name=f"CPU Cryptographic Extensions ({platform.processor() or platform.machine()})",
                status="active",
                algorithm="Hardware-Accelerated AES / SHA",
                quantum_safe=True,  # Symmetric/hash instructions remain quantum-resistant
                shor_vulnerable=False,
                security_findings=[],
                raw_metadata={"features": cpu_features}
            ))

        return findings