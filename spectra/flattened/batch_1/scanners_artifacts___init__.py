"""
spectra.scanners.artifacts
===============================
Coordinates discovery and auditing of cryptographic artifacts:
X.509 certificates, private keys, compiled binaries, shared libraries,
and container definitions (Dockerfiles/Containerfiles).
"""

from pathlib import Path
from typing import Any, Dict, List

from spectra.config import ScanConfig
from spectra.utils.logger import log_info, log_step

from .binary_scanner import BinaryFinding, BinaryScanner
from .cert_scanner import CertFinding, CertScanner
from .container_scanner import ContainerFinding, ContainerScanner


class ArtifactScanOrchestrator:
    """Dispatches artifact scanners across target directories."""

    def __init__(self, config: ScanConfig):
        self.config = config
        self.cert_scanner = CertScanner()
        self.binary_scanner = BinaryScanner()
        self.container_scanner = ContainerScanner()

    def scan(self, target_dir: Path) -> List[Dict[str, Any]]:
        """Scans the target directory for certificates, keys, binaries, and container definitions."""
        log_step(f"Scanning cryptographic artifacts in: {target_dir}")
        excluded = self.config.source_scanner.excluded_directories

        # 1. Scan Certificates & Keys
        cert_findings: List[CertFinding] = self.cert_scanner.scan_directory(
            target_dir, excluded_dirs=excluded
        )
        log_info(f"Discovered {len(cert_findings)} certificate/key artifact(s).")

        # 2. Scan Binaries & Shared Libraries
        binary_findings: List[BinaryFinding] = self.binary_scanner.scan_directory(
            target_dir, excluded_dirs=excluded
        )
        log_info(f"Discovered {len(binary_findings)} binary/library artifact(s) with crypto linkage.")

        # 3. Scan Container Definitions & Dockerfiles
        container_findings: List[ContainerFinding] = self.container_scanner.scan_directory(
            target_dir, excluded_dirs=excluded
        )
        log_info(f"Discovered {len(container_findings)} container cryptographic finding(s).")

        # Serialize all findings to standard dictionaries
        all_findings: List[Dict[str, Any]] = []
        for c in cert_findings:
            all_findings.append(c.to_dict())
        for b in binary_findings:
            all_findings.append(b.to_dict())
        for ct in container_findings:
            all_findings.append(ct.to_dict())

        return all_findings