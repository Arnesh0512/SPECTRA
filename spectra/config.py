"""
spectra.config
===================
Dynamic programmatic configuration builder for Spectra interactive TUI.
"""

from pathlib import Path
from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field


class ScanTargets(BaseModel):
    project_root: str = Field(default=".", description="Root directory to scan for code and artifacts")
    container_target: Optional[str] = Field(default=None, description="Name or ID of Docker container scanned")
    domains: List[str] = Field(default_factory=list, description="Remote host:port targets for TLS inspection")
    aws_regions: List[str] = Field(default_factory=lambda: ["us-east-1"], description="AWS regions for discovery")
    nginx_config_paths: List[str] = Field(default_factory=list, description="Filesystem paths to nginx configurations")


class ScannerToggles(BaseModel):
    enable_source: bool = Field(default=True, description="Scan source code AST and patterns")
    enable_artifacts: bool = Field(default=True, description="Scan binaries, certs, and containers")
    enable_runtime: bool = Field(default=True, description="Scan active local runtime packages and processes")
    enable_infrastructure: bool = Field(default=True, description="Scan AWS/Azure KMS/ACM/HSM and Terraform")
    enable_network: bool = Field(default=True, description="Scan endpoints, TLS handshakes, and web servers")
    scan_dependencies: bool = Field(default=True, description="Scan dependency manifests")


class SourceScannerConfig(BaseModel):
    use_ripgrep: bool = Field(default=True, description="Always true for optimized AST matching")
    max_header_lines_checked: int = Field(default=100, description="Header lines evaluated")
    excluded_directories: List[str] = Field(
        default_factory=lambda: [
            ".git", "node_modules", "vendor", "target",
            "dist", "build", ".venv", "venv", "__pycache__"
        ],
        description="Directories ignored across all filesystem walkers"
    )


class NetworkConfig(BaseModel):
    endpoints: List[str] = Field(default_factory=list, description="Remote host:port targets for TLS inspection")


class AWSConfig(BaseModel):
    enabled: bool = Field(
        default_factory=lambda: (Path.home() / ".aws").exists(),
        description="Auto-enabled if ~/.aws credentials exist"
    )
    regions: List[str] = Field(default_factory=lambda: ["us-east-1"], description="AWS regions to scan")


class AzureConfig(BaseModel):
    enabled: bool = Field(
        default_factory=lambda: (Path.home() / ".azure").exists(),
        description="Auto-enabled if ~/.azure credentials exist"
    )
    subscription_id: Optional[str] = Field(default=None, description="Azure subscription ID")


class MoscaConfig(BaseModel):
    default_data_classification: str = Field(default="corporate_financials", description="Default shelf life profile")
    crqc_scenario: str = Field(default="central", description="pessimistic, central, or optimistic")
    environment_type: str = Field(default="cloud_native", description="cloud_native, hybrid, on_prem_legacy, embedded")


class OutputConfig(BaseModel):
    format: str = Field(default="cyclonedx_1.6_json", description="Target CBOM export format")
    output_file: str = Field(default="cbom.json", description="Destination file for generated CBOM")


class ScanConfig(BaseModel):
    scan_targets: ScanTargets = Field(default_factory=ScanTargets)
    scanners: ScannerToggles = Field(default_factory=ScannerToggles)
    source_scanner: SourceScannerConfig = Field(default_factory=SourceScannerConfig)
    network: NetworkConfig = Field(default_factory=NetworkConfig)
    aws: AWSConfig = Field(default_factory=AWSConfig)
    azure: AzureConfig = Field(default_factory=AzureConfig)
    mosca_parameters: MoscaConfig = Field(default_factory=MoscaConfig)
    output: OutputConfig = Field(default_factory=OutputConfig)