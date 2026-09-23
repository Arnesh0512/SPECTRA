"""
crypto_recon.scanners
=====================
Unified scanning layer coordinating all four reconnaissance domains:
- Source code AST and pattern analysis (source)
- Disk artifacts, certificates, binaries, and containers (artifacts)
- Infrastructure-as-Code and cloud assets (infrastructure)
- Network endpoints, TLS handshakes, and protocol configs (network)
"""

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

from crypto_recon.config import ScanConfig
from crypto_recon.scanners.artifacts import ArtifactScanOrchestrator
from crypto_recon.scanners.infrastructure import InfrastructureScanOrchestrator
from crypto_recon.scanners.network import NetworkScanOrchestrator
from crypto_recon.scanners.source import SourceScanOrchestrator
from crypto_recon.utils.logger import log_header, log_info, log_step


@dataclass
class ScanResults:
    """Encapsulates raw findings collected across all scanning domains."""
    source_findings: List[Dict[str, Any]] = field(default_factory=list)
    artifact_findings: List[Dict[str, Any]] = field(default_factory=list)
    infrastructure_findings: List[Dict[str, Any]] = field(default_factory=list)
    network_findings: List[Dict[str, Any]] = field(default_factory=list)

    @property
    def all_findings(self) -> List[Dict[str, Any]]:
        """Combines findings from all domains into a single flat list."""
        return (
            self.source_findings
            + self.artifact_findings
            + self.infrastructure_findings
            + self.network_findings
        )

    @property
    def total_count(self) -> int:
        return len(self.all_findings)


class MasterScanner:
    """Master coordinator executing enabled domain scanners against given targets."""

    def __init__(self, config: ScanConfig):
        self.config = config
        self.source_orchestrator = SourceScanOrchestrator(config=config)
        self.artifact_orchestrator = ArtifactScanOrchestrator(config=config)
        self.infrastructure_orchestrator = InfrastructureScanOrchestrator(config=config)
        self.network_orchestrator = NetworkScanOrchestrator(config=config)

    def scan_all(
        self,
        target_dir: Optional[Path] = None,
        endpoints: Optional[List[str]] = None,
    ) -> ScanResults:
        """
        Executes active scanners across configured targets.

        :param target_dir: Local filesystem directory to audit.
        :param endpoints: Optional list of network endpoints (host:port) to scan.
        :return: Consolidated ScanResults instance.
        """
        results = ScanResults()
        resolved_dir = target_dir.resolve() if target_dir and target_dir.exists() else None

        log_header("Executing Multi-Domain Cryptographic Reconnaissance")

        # 1. Source Code Scanning
        if resolved_dir:
            log_step("Domain 1/4: Source Code Analysis")
            source_raw = self.source_orchestrator.scan(resolved_dir)
            results.source_findings = [f.to_dict() for f in source_raw]
            log_info(f"Source scan completed: {len(results.source_findings)} findings.")

        # 2. Cryptographic Artifacts Scanning
        if resolved_dir:
            log_step("Domain 2/4: Cryptographic Artifacts Analysis")
            results.artifact_findings = self.artifact_orchestrator.scan(resolved_dir)
            log_info(f"Artifact scan completed: {len(results.artifact_findings)} findings.")

        # 3. Infrastructure and Cloud Scanning
        log_step("Domain 3/4: Infrastructure & IaC Analysis")
        results.infrastructure_findings = self.infrastructure_orchestrator.scan(target_dir=resolved_dir)
        log_info(f"Infrastructure scan completed: {len(results.infrastructure_findings)} findings.")

        # 4. Network and Protocol Scanning
        log_step("Domain 4/4: Network & Protocol Analysis")
        target_eps = endpoints or self.config.network.endpoints
        results.network_findings = self.network_orchestrator.scan(
            target_dir=resolved_dir,
            endpoints=target_eps
        )
        log_info(f"Network scan completed: {len(results.network_findings)} findings.")

        log_header(f"Reconnaissance Completed — Total Raw Findings: {results.total_count}")
        return results