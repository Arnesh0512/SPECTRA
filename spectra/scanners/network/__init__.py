"""
spectra.scanners.network
=============================
Coordinates discovery and auditing of network cryptography:
Active TLS handshakes (endpoint_scanner), static web server configurations (nginx_scanner),
and protocol parameters (protocol_scanner).
"""

from pathlib import Path
from typing import Any, Dict, List, Optional

from spectra.config import ScanConfig
from spectra.utils.logger import log_info, log_step

from .endpoint_scanner import EndpointScanner, NetworkEndpointFinding
from .nginx_scanner import NginxFinding, NginxScanner
from .protocol_scanner import ProtocolFinding, ProtocolScanner


class NetworkScanOrchestrator:
    """Dispatches static network configuration audits and live endpoint handshakes."""

    def __init__(self, config: ScanConfig):
        self.config = config
        self.endpoint_scanner = EndpointScanner()
        self.nginx_scanner = NginxScanner()
        self.protocol_scanner = ProtocolScanner()

    def scan(self, target_dir: Optional[Path] = None, endpoints: Optional[List[str]] = None) -> List[Dict[str, Any]]:
        """
        Executes both static network audits and live endpoint handshakes.

        :param target_dir: Optional root directory to scan for Nginx and protocol configurations.
        :param endpoints: Optional list of 'host:port' or 'domain' strings to scan live.
        """
        all_findings: List[Dict[str, Any]] = []

        # 1. Static Configuration Auditing (Nginx, SSH)
        if target_dir and target_dir.exists():
            log_step(f"Scanning network configuration files in: {target_dir}")
            excluded = self.config.source_scanner.excluded_directories

            nginx_findings: List[NginxFinding] = self.nginx_scanner.scan_directory(
                target_dir, excluded_dirs=excluded
            )
            log_info(f"Discovered {len(nginx_findings)} Nginx/web server cryptographic block(s).")
            for nf in nginx_findings:
                all_findings.append(nf.to_dict())

            proto_findings: List[ProtocolFinding] = self.protocol_scanner.scan_directory(
                target_dir, excluded_dirs=excluded
            )
            log_info(f"Discovered {len(proto_findings)} protocol configuration(s).")
            for pf in proto_findings:
                all_findings.append(pf.to_dict())

        # 2. Live Network Endpoint Scanning
        target_endpoints = endpoints or self.config.network.endpoints
        if target_endpoints:
            log_step(f"Executing active TLS handshakes against {len(target_endpoints)} endpoint(s)")
            for ep_str in target_endpoints:
                host, port = self._parse_endpoint(ep_str)
                finding: Optional[NetworkEndpointFinding] = self.endpoint_scanner.scan_endpoint(host, port)
                if finding:
                    all_findings.append(finding.to_dict())
                    log_info(f"Handshake successful for {host}:{port} -> {finding.cipher_suite}")
                else:
                    log_info(f"Unable to complete TLS handshake with {host}:{port}")

        return all_findings

    def _parse_endpoint(self, ep_str: str) -> tuple[str, int]:
        """Parses 'example.com:8443' or 'example.com' into (host, port)."""
        ep_clean = ep_str.strip().replace("https://", "").replace("http://", "").rstrip("/")
        if ":" in ep_clean:
            parts = ep_clean.split(":")
            try:
                return parts[0], int(parts[1])
            except ValueError:
                return parts[0], 443
        return ep_clean, 443