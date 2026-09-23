from pathlib import Path
from typing import List, Optional, Dict, Any
import json
import yaml
from pydantic import BaseModel, Field


class ScanTargets(BaseModel):
    project_root: str = Field(default=".", description="Root directory to scan for code and artifacts")
    domains: List[str] = Field(default_factory=list, description="Remote host:port targets for TLS inspection")
    aws_regions: List[str] = Field(default_factory=lambda: ["us-east-1"], description="AWS regions for KMS/ACM discovery")
    nginx_config_paths: List[str] = Field(default_factory=list, description="Filesystem paths to nginx configurations")


class ScannerToggles(BaseModel):
    enable_source: bool = Field(default=True, description="Scan source code AST and patterns")
    enable_artifacts: bool = Field(default=True, description="Scan binaries, certs, and containers")
    enable_infrastructure: bool = Field(default=True, description="Scan AWS KMS/ACM/HSM and Terraform")
    enable_network: bool = Field(default=True, description="Scan endpoints, TLS handshakes, and web servers")


class SourceScannerConfig(BaseModel):
    use_ripgrep: bool = Field(default=True, description="Use ripgrep binary filter if available")
    max_header_lines_checked: int = Field(default=100, description="Header lines evaluated during fast filter")
    excluded_directories: List[str] = Field(
        default_factory=lambda: [
            ".git", "node_modules", "vendor", "target",
            "dist", "build", ".venv", "venv", "__pycache__"
        ],
        description="Directories ignored across all filesystem walkers"
    )


class MoscaConfig(BaseModel):
    default_data_classification: str = Field(default="corporate_financials", description="Key matching cbom_policy.json shelf lives")
    crqc_scenario: str = Field(default="central", description="pessimistic, central, or optimistic")
    environment_type: str = Field(default="cloud_native", description="cloud_native, hybrid, on_prem_legacy, or embedded")


class OutputConfig(BaseModel):
    format: str = Field(default="cyclonedx_1.6_json", description="Target CBOM export format")
    output_file: str = Field(default="cbom.json", description="Destination file for generated CBOM")


class ScanConfig(BaseModel):
    scan_targets: ScanTargets = Field(default_factory=ScanTargets)
    scanners: ScannerToggles = Field(default_factory=ScannerToggles)
    source_scanner: SourceScannerConfig = Field(default_factory=SourceScannerConfig)
    mosca_parameters: MoscaConfig = Field(default_factory=MoscaConfig)
    output: OutputConfig = Field(default_factory=OutputConfig)


def load_policy(policy_path: Optional[Path] = None) -> Dict[str, Any]:
    """Loads the centralized CBOM and quantum risk policy (cbom_policy.json)."""
    if policy_path is None:
        # Defaults to root cbom_policy.json relative to package installation
        policy_path = Path(__file__).resolve().parent.parent / "cbom_policy.json"

    if not policy_path.exists():
        return {}

    with open(policy_path, "r", encoding="utf-8") as f:
        return json.load(f)


def load_config(
    config_path: Optional[Path] = None,
    cli_overrides: Optional[Dict[str, Any]] = None
) -> ScanConfig:
    """
    Loads configuration from a YAML file, applies defaults for any missing blocks,
    and merges user-provided CLI overrides.
    """
    raw_data: Dict[str, Any] = {}

    if config_path and Path(config_path).exists():
        with open(config_path, "r", encoding="utf-8") as f:
            loaded = yaml.safe_load(f)
            if isinstance(loaded, dict):
                raw_data = loaded

    # Apply top-level CLI overrides if specified
    if cli_overrides:
        if "project_root" in cli_overrides and cli_overrides["project_root"]:
            raw_data.setdefault("scan_targets", {})["project_root"] = cli_overrides["project_root"]

        if "domains" in cli_overrides and cli_overrides["domains"]:
            raw_data.setdefault("scan_targets", {})["domains"] = cli_overrides["domains"]

        if "aws_regions" in cli_overrides and cli_overrides["aws_regions"]:
            raw_data.setdefault("scan_targets", {})["aws_regions"] = cli_overrides["aws_regions"]

        if "output_file" in cli_overrides and cli_overrides["output_file"]:
            raw_data.setdefault("output", {})["output_file"] = cli_overrides["output_file"]

    return ScanConfig(**raw_data)