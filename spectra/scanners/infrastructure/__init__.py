"""
spectra.scanners.infrastructure
====================================
Coordinates discovery and risk auditing for infrastructure cryptographic assets:
Terraform (.tf) configurations, IaC manifests (Kubernetes, CloudFormation),
cloud environments (AWS KMS & ACM, Azure Key Vault), and host hardware devices (TPM, HSM, CPU).
"""

from pathlib import Path
from typing import Any, Dict, List, Optional

from spectra.config import ScanConfig
from spectra.utils.logger import log_info, log_step, log_warning

from .aws_scanner import AWSFinding, AWSScanner
from .azure_scanner import AzureFinding, AzureScanner
from .hardware_scanner import HardwareFinding, HardwareScanner
from .iac_scanner import IaCFinding, IaCScanner
from .terraform_scanner import TerraformFinding, TerraformScanner


class InfrastructureScanOrchestrator:
    """Dispatches scanners across Terraform files, IaC manifests, hardware modules, AWS, and Azure cloud environments."""

    def __init__(self, config: ScanConfig):
        self.config = config
        self.terraform_scanner = TerraformScanner()
        self.iac_scanner = IaCScanner()
        self.hardware_scanner = HardwareScanner()

        # Safely extract AWS regions from config if present, otherwise default to us-east-1
        aws_cfg = getattr(config, "aws", None)
        regions = getattr(aws_cfg, "regions", ["us-east-1"]) if aws_cfg else ["us-east-1"]
        self.aws_scanner = AWSScanner(regions=regions)

        # Initialize Azure scanner
        self.azure_scanner = AzureScanner()

    def scan(self, target_dir: Optional[Path] = None) -> List[Dict[str, Any]]:
        """Scans local Terraform directories, IaC manifests, host hardware, AWS, and Azure cloud environments."""
        all_findings: List[Dict[str, Any]] = []
        excluded = self.config.source_scanner.excluded_directories

        # 1. Scan Terraform IaC Configurations (.tf files)
        if target_dir and target_dir.exists():
            log_step(f"Scanning Terraform configurations in: {target_dir}")
            tf_findings: List[TerraformFinding] = self.terraform_scanner.scan_directory(
                target_dir=target_dir,
                excluded_dirs=excluded
            )
            log_info(f"Discovered {len(tf_findings)} cryptographic resource(s) in Terraform files.")
            for f in tf_findings:
                all_findings.append(f.to_dict())

        # 2. Scan Generic IaC Manifests (Kubernetes YAML, CloudFormation JSON/YAML)
        if target_dir and target_dir.exists():
            log_step(f"Scanning generic IaC manifests in: {target_dir}")
            iac_findings: List[IaCFinding] = self.iac_scanner.scan_directory(
                target_dir=target_dir,
                excluded_dirs=excluded
            )
            log_info(f"Discovered {len(iac_findings)} cryptographic resource(s) in generic IaC manifests.")
            for f in iac_findings:
                all_findings.append(f.to_dict())

        # 3. Scan Host Hardware (TPMs, PKCS#11 HSMs, CPU Crypto Acceleration)
        log_step("Scanning host cryptographic hardware (TPM, HSM, CPU instruction sets)")
        hw_findings: List[HardwareFinding] = self.hardware_scanner.scan()
        log_info(f"Discovered {len(hw_findings)} hardware cryptographic device(s)/capability.")
        for f in hw_findings:
            all_findings.append(f.to_dict())

        # 4. Scan AWS Cloud Resources (KMS CMKs, ACM Certificates if enabled)
        aws_cfg = getattr(self.config, "aws", None)
        aws_enabled = getattr(aws_cfg, "enabled", False) if aws_cfg else False

        if aws_enabled:
            log_step("Auditing AWS Cloud Cryptographic Assets (KMS & ACM)")
            if not self.aws_scanner.is_available():
                log_warning("boto3 is not installed or importable; skipping live AWS scan.")
            else:
                aws_findings: List[AWSFinding] = self.aws_scanner.scan()
                log_info(f"Discovered {len(aws_findings)} cryptographic asset(s) in AWS.")
                for f in aws_findings:
                    all_findings.append(f.to_dict())

        # 5. Scan Azure Cloud Resources (Key Vault Keys & Certificates if enabled)
        azure_cfg = getattr(self.config, "azure", None)
        azure_enabled = getattr(azure_cfg, "enabled", False) if azure_cfg else False

        if azure_enabled:
            log_step("Auditing Azure Cloud Cryptographic Assets (Key Vault Keys & Certificates)")
            if not self.azure_scanner.is_available():
                log_warning("Azure SDK libraries (azure-identity, azure-mgmt-keyvault, azure-keyvault-keys) are not installed; skipping live Azure scan.")
            else:
                azure_findings: List[AzureFinding] = self.azure_scanner.scan()
                log_info(f"Discovered {len(azure_findings)} cryptographic asset(s) in Azure.")
                for f in azure_findings:
                    all_findings.append(f.to_dict())

        return all_findings