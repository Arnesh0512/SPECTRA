"""
crypto_recon.scanners.network.protocol_scanner
==============================================
Network protocol cryptographic property scanner.
Audits cryptographic posture of protocols such as SSH, IPsec, and plain-text
protocols, inspecting key exchange algorithms, ciphers, and MAC algorithms.
"""

from dataclasses import dataclass, field
from pathlib import Path
import re
from typing import Any, Dict, List, Optional


@dataclass
class ProtocolFinding:
    """Represents cryptographic posture of a network protocol or service config."""
    source_domain: str = "network"
    protocol: str = "ssh"  # ssh, ipsec, plaintext
    file_path: str = ""
    line_number: int = 0
    service_target: str = ""
    kex_algorithms: List[str] = field(default_factory=list)
    ciphers: List[str] = field(default_factory=list)
    macs: List[str] = field(default_factory=list)
    host_key_algorithms: List[str] = field(default_factory=list)
    quantum_safe: bool = False
    shor_vulnerable: bool = True
    security_findings: List[Dict[str, str]] = field(default_factory=list)
    raw_metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "source_domain": self.source_domain,
            "protocol": self.protocol,
            "file_path": self.file_path,
            "line_number": self.line_number,
            "service_target": self.service_target,
            "kex_algorithms": self.kex_algorithms,
            "ciphers": self.ciphers,
            "macs": self.macs,
            "host_key_algorithms": self.host_key_algorithms,
            "quantum_safe": self.quantum_safe,
            "shor_vulnerable": self.shor_vulnerable,
            "security_findings": self.security_findings,
            "raw_metadata": self.raw_metadata,
        }


# Directives commonly found in sshd_config or ssh_config
SSH_DIRECTIVE_REGEX = re.compile(
    r"^\s*(?P<key>KexAlgorithms|Ciphers|MACs|HostKeyAlgorithms)\s+(?P<val>[^\n#]+)",
    re.MULTILINE | re.IGNORECASE
)


class ProtocolScanner:
    """Scans protocol configuration files (e.g., sshd_config) for cryptographic compliance."""

    CONFIG_NAMES = {"sshd_config", "ssh_config", "ipsec.conf"}

    def scan_directory(self, target_dir: Path, excluded_dirs: Optional[List[str]] = None) -> List[ProtocolFinding]:
        findings: List[ProtocolFinding] = []
        excluded = set(excluded_dirs or [])

        for path in target_dir.rglob("*"):
            if not path.is_file():
                continue
            if any(part in excluded for part in path.parts):
                continue
            if path.name.lower() in self.CONFIG_NAMES:
                finding = self.scan_file(path)
                if finding:
                    findings.append(finding)

        return findings

    def scan_file(self, file_path: Path) -> Optional[ProtocolFinding]:
        try:
            with open(file_path, "r", encoding="utf-8", errors="replace") as f:
                content = f.read()
        except Exception:
            return None

        if "ssh" in file_path.name.lower():
            return self._parse_ssh_config(file_path, content)
        return None

    def _parse_ssh_config(self, file_path: Path, content: str) -> Optional[ProtocolFinding]:
        kex_list: List[str] = []
        ciphers_list: List[str] = []
        macs_list: List[str] = []
        hostkeys_list: List[str] = []
        sec_findings = []

        for match in SSH_DIRECTIVE_REGEX.finditer(content):
            key = match.group("key").lower()
            val = [x.strip() for x in match.group("val").split(",") if x.strip()]

            if key == "kexalgorithms":
                kex_list.extend(val)
            elif key == "ciphers":
                ciphers_list.extend(val)
            elif key == "macs":
                macs_list.extend(val)
            elif key == "hostkeyalgorithms":
                hostkeys_list.extend(val)

        if not (kex_list or ciphers_list or macs_list or hostkeys_list):
            return None

        # Audit weak SSH KEX (e.g. diffie-hellman-group1-sha1)
        for kex in kex_list:
            if "group1-sha1" in kex or "group14-sha1" in kex:
                sec_findings.append({
                    "issue": f"Legacy SHA1-based SSH KexAlgorithm configured: {kex}",
                    "severity": "HIGH"
                })

        # Audit weak SSH ciphers (e.g. 3des-cbc, arcfour)
        for cipher in ciphers_list:
            if any(w in cipher for w in ["3des", "arcfour", "blowfish", "cast128"]):
                sec_findings.append({
                    "issue": f"Deprecated SSH cipher configured: {cipher}",
                    "severity": "CRITICAL"
                })
            elif "cbc" in cipher:
                sec_findings.append({
                    "issue": f"CBC-mode cipher in SSH configuration: {cipher}",
                    "severity": "MEDIUM"
                })

        # Audit weak SSH MACs (e.g. hmac-md5, hmac-sha1)
        for mac in macs_list:
            if "md5" in mac or "sha1" in mac:
                sec_findings.append({
                    "issue": f"Weak SSH MAC algorithm configured: {mac}",
                    "severity": "HIGH"
                })

        # Check for Post-Quantum SSH Key Exchange
        # OpenSSH 9.0+ defaults to sntrup761x25519-sha512@openssh.com or hybrid ML-KEM
        quantum_safe = any(
            "sntrup761" in k.lower() or "mlkem" in k.lower() for k in kex_list
        )
        shor_vuln = not quantum_safe

        return ProtocolFinding(
            source_domain="network",
            protocol="ssh",
            file_path=str(file_path.resolve()),
            line_number=1,
            service_target="sshd",
            kex_algorithms=kex_list,
            ciphers=ciphers_list,
            macs=macs_list,
            host_key_algorithms=hostkeys_list,
            quantum_safe=quantum_safe,
            shor_vulnerable=shor_vuln,
            security_findings=sec_findings,
            raw_metadata={"config_type": "sshd_config"}
        )