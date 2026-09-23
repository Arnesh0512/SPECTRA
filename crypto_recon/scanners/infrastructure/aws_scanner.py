"""
crypto_recon.scanners.infrastructure.aws_scanner
================================================
Audits AWS cryptographic assets via boto3.
Discovers and inspects AWS KMS encryption keys and AWS Certificate Manager (ACM)
certificates across specified regions for key lengths, rotation, and Shor vulnerability.
"""

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

try:
    import boto3
    from botocore.exceptions import BotoCoreError, ClientError
    BOTO3_AVAILABLE = True
except ImportError:
    BOTO3_AVAILABLE = False


@dataclass
class AWSFinding:
    """Represents a discovered AWS cryptographic asset."""
    source_domain: str = "infrastructure"
    infra_provider: str = "aws"
    service: str = ""  # kms, acm
    region: str = ""
    resource_arn: str = ""
    resource_id: str = ""
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
            "region": self.region,
            "resource_arn": self.resource_arn,
            "resource_id": self.resource_id,
            "algorithm": self.algorithm,
            "key_spec": self.key_spec,
            "key_size": self.key_size,
            "quantum_safe": self.quantum_safe,
            "shor_vulnerable": self.shor_vulnerable,
            "security_findings": self.security_findings,
            "raw_metadata": self.raw_metadata,
        }


class AWSScanner:
    """Discovers cryptographic configurations across AWS services."""

    def __init__(self, regions: Optional[List[str]] = None):
        self.regions = regions or ["us-east-1"]

    def is_available(self) -> bool:
        """Returns True if boto3 is installed."""
        return BOTO3_AVAILABLE

    def scan(self) -> List[AWSFinding]:
        """Scans KMS and ACM across configured AWS regions."""
        if not self.is_available():
            return []

        findings: List[AWSFinding] = []
        for region in self.regions:
            findings.extend(self._scan_kms(region))
            findings.extend(self._scan_acm(region))

        return findings

    def _scan_kms(self, region: str) -> List[AWSFinding]:
        findings: List[AWSFinding] = []
        try:
            kms = boto3.client("kms", region_name=region)
            paginator = kms.get_paginator("list_keys")

            for page in paginator.paginate():
                for key_entry in page.get("Keys", []):
                    key_id = key_entry["KeyId"]
                    try:
                        desc = kms.describe_key(KeyId=key_id)["KeyMetadata"]
                        if desc.get("KeyManager") != "CUSTOMER":
                            continue  # Focus on Customer Managed Keys (CMKs)

                        finding = self._evaluate_kms_key(kms, desc, region)
                        if finding:
                            findings.append(finding)
                    except (ClientError, BotoCoreError):
                        continue
        except (ClientError, BotoCoreError):
            pass

        return findings

    def _evaluate_kms_key(self, kms_client: Any, metadata: Dict[str, Any], region: str) -> AWSFinding:
        key_id = metadata["KeyId"]
        arn = metadata.get("Arn", key_id)
        spec = metadata.get("CustomerMasterKeySpec") or metadata.get("KeySpec", "SYMMETRIC_DEFAULT")
        usage = metadata.get("KeyUsage", "ENCRYPT_DECRYPT")

        # Check key rotation status
        rotation_enabled = False
        sec_findings = []
        try:
            rotation_resp = kms_client.get_key_rotation_status(KeyId=key_id)
            rotation_enabled = rotation_resp.get("KeyRotationEnabled", False)
            if not rotation_enabled and spec == "SYMMETRIC_DEFAULT":
                sec_findings.append({
                    "issue": "Automatic annual KMS key rotation is disabled",
                    "severity": "MEDIUM",
                })
        except (ClientError, BotoCoreError):
            pass

        # Determine algorithm and quantum vulnerability
        algo = "AES-GCM"
        key_size = 256
        shor_vuln = False
        quantum_safe = True

        if "RSA" in spec:
            algo = "RSA"
            shor_vuln = True
            quantum_safe = False
            if "2048" in spec:
                key_size = 2048
            elif "3072" in spec:
                key_size = 3072
            elif "4096" in spec:
                key_size = 4096
        elif "ECC" in spec or "SM2" in spec:
            algo = "ECC"
            shor_vuln = True
            quantum_safe = False
            key_size = 256

        return AWSFinding(
            source_domain="infrastructure",
            infra_provider="aws",
            service="kms",
            region=region,
            resource_arn=arn,
            resource_id=key_id,
            algorithm=algo,
            key_spec=spec,
            key_size=key_size,
            quantum_safe=quantum_safe,
            shor_vulnerable=shor_vuln,
            security_findings=sec_findings,
            raw_metadata={
                "key_usage": usage,
                "rotation_enabled": rotation_enabled,
                "creation_date": str(metadata.get("CreationDate")),
            },
        )

    def _scan_acm(self, region: str) -> List[AWSFinding]:
        findings: List[AWSFinding] = []
        try:
            acm = boto3.client("acm", region_name=region)
            paginator = acm.get_paginator("list_certificates")

            for page in paginator.paginate():
                for summary in page.get("CertificateSummaryList", []):
                    cert_arn = summary["CertificateArn"]
                    try:
                        desc = acm.describe_certificate(CertificateArn=cert_arn)["Certificate"]
                        finding = self._evaluate_acm_cert(desc, region)
                        if finding:
                            findings.append(finding)
                    except (ClientError, BotoCoreError):
                        continue
        except (ClientError, BotoCoreError):
            pass

        return findings

    def _evaluate_acm_cert(self, cert: Dict[str, Any], region: str) -> AWSFinding:
        arn = cert.get("CertificateArn", "")
        domain = cert.get("DomainName", "unknown")
        key_algo = cert.get("KeyAlgorithm", "RSA-2048")

        shor_vuln = True
        quantum_safe = False
        key_size = 2048
        if "RSA_3072" in key_algo:
            key_size = 3072
        elif "RSA_4096" in key_algo:
            key_size = 4096
        elif "EC_prime256v1" in key_algo or "EC_secp384r1" in key_algo:
            key_size = 256 if "256" in key_algo else 384

        sec_findings = []
        not_after = cert.get("NotAfter")
        if not_after:
            now = datetime.now(timezone.utc)
            days_left = (not_after - now).days
            if days_left < 30:
                sec_findings.append({
                    "issue": f"ACM certificate expiring in {days_left} days",
                    "severity": "MEDIUM",
                })

        return AWSFinding(
            source_domain="infrastructure",
            infra_provider="aws",
            service="acm",
            region=region,
            resource_arn=arn,
            resource_id=domain,
            algorithm=key_algo,
            key_spec=key_algo,
            key_size=key_size,
            quantum_safe=quantum_safe,
            shor_vulnerable=shor_vuln,
            security_findings=sec_findings,
            raw_metadata={
                "type": cert.get("Type"),
                "status": cert.get("Status"),
                "in_use_by": cert.get("InUseBy", []),
            },
        )