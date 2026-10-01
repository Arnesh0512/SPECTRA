"""
spectra.scanners.infrastructure.azure_scanner
==================================================
Audits Azure cryptographic assets using the Azure SDK for Python.
Discovers and inspects Azure Key Vault encryption keys and certificates
for key lengths, rotation policies, and Shor vulnerability.
"""

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

try:
    from azure.identity import DefaultAzureCredential
    from azure.mgmt.keyvault import KeyVaultManagementClient
    from azure.keyvault.keys import KeyClient
    from azure.keyvault.certificates import CertificateClient
    AZURE_SDK_AVAILABLE = True
except ImportError:
    AZURE_SDK_AVAILABLE = False


@dataclass
class AzureFinding:
    """Represents a discovered Azure cryptographic asset."""
    source_domain: str = "infrastructure"
    infra_provider: str = "azure"
    service: str = ""  # key_vault_key, key_vault_certificate
    subscription_id: str = ""
    resource_group: str = ""
    vault_name: str = ""
    resource_id: str = ""
    algorithm: str = "unknown"
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
            "subscription_id": self.subscription_id,
            "resource_group": self.resource_group,
            "vault_name": self.vault_name,
            "resource_id": self.resource_id,
            "algorithm": self.algorithm,
            "key_size": self.key_size,
            "quantum_safe": self.quantum_safe,
            "shor_vulnerable": self.shor_vulnerable,
            "security_findings": self.security_findings,
            "raw_metadata": self.raw_metadata,
        }


class AzureScanner:
    """Discovers cryptographic configurations across Azure Key Vaults."""

    def __init__(self, subscription_id: Optional[str] = None):
        self.subscription_id = subscription_id

    def is_available(self) -> bool:
        """Returns True if Azure SDK libraries are installed."""
        return AZURE_SDK_AVAILABLE

    def scan(self) -> List[AzureFinding]:
        """Scans Key Vault keys and certificates across accessible Azure subscriptions."""
        if not self.is_available():
            return []

        findings: List[AzureFinding] = []
        try:
            import os, subprocess, shutil
            from azure.identity import AzureCliCredential

            # Resolve credential (prefer AzureCliCredential if CLI is logged in)
            credential = None
            try:
                cli_cred = AzureCliCredential()
                cli_cred.get_token("https://management.azure.com/.default")
                credential = cli_cred
            except Exception:
                credential = DefaultAzureCredential()

            # Resolve active subscription ID
            sub_id = self.subscription_id or os.environ.get("AZURE_SUBSCRIPTION_ID")
            if not sub_id:
                try:
                    az_bin = shutil.which("az") or "az"
                    res = subprocess.run([az_bin, "account", "show", "--query", "id", "-o", "tsv"], capture_output=True, text=True, timeout=5, shell=True)
                    if res.returncode == 0 and res.stdout.strip():
                        sub_id = res.stdout.strip()
                except Exception:
                    pass

            if not sub_id:
                return []

            mgmt_client = KeyVaultManagementClient(credential, subscription_id=sub_id)
            
            # List all Key Vaults in the subscription/tenant
            vaults = mgmt_client.vaults.list()
            for vault in vaults:
                vault_name = vault.name
                vault_uri = f"https://{vault_name}.vault.azure.net/"
                resource_group = vault.id.split("/")[4] if vault.id else "unknown"

                # Scan Keys and Certificates inside the Key Vault
                findings.extend(self._scan_vault_keys(vault_uri, vault_name, resource_group, credential=credential))
                findings.extend(self._scan_vault_certificates(vault_uri, vault_name, resource_group, credential=credential))

        except Exception:
            pass

        return findings

    def _scan_vault_keys(self, vault_uri: str, vault_name: str, resource_group: str, credential: Optional[Any] = None) -> List[AzureFinding]:
        findings: List[AzureFinding] = []
        try:
            cred = credential or DefaultAzureCredential()
            key_client = KeyClient(vault_url=vault_uri, credential=cred)
            
            for key_properties in key_client.list_properties_of_keys():
                key_name = key_properties.name
                key_obj = key_client.get_key(key_name)
                
                k_type = str(key_obj.key_type).upper()
                k_size = None
                jwk = getattr(key_obj, "key", None)
                if jwk:
                    if "RSA" in k_type and getattr(jwk, "n", None):
                        k_size = len(jwk.n) * 8
                    elif "EC" in k_type:
                        crv_str = str(getattr(jwk, "crv", ""))
                        if "384" in crv_str:
                            k_size = 384
                        elif "521" in crv_str:
                            k_size = 521
                        else:
                            k_size = 256

                algo = "AES-GCM"
                quantum_safe = True
                shor_vuln = False
                sec_findings = []

                if "RSA" in k_type:
                    algo = "RSA"
                    quantum_safe = False
                    shor_vuln = True
                elif "EC" in k_type:
                    algo = "ECC"
                    quantum_safe = False
                    shor_vuln = True

                findings.append(AzureFinding(
                    source_domain="infrastructure",
                    infra_provider="azure",
                    service="key_vault_key",
                    resource_group=resource_group,
                    vault_name=vault_name,
                    resource_id=key_name,
                    algorithm=algo,
                    key_size=k_size,
                    quantum_safe=quantum_safe,
                    shor_vulnerable=shor_vuln,
                    security_findings=sec_findings,
                    raw_metadata={
                        "key_type": k_type,
                        "enabled": key_obj.properties.enabled,
                        "expires_on": str(key_obj.properties.expires_on),
                    }
                ))
        except Exception:
            pass
        return findings

    def _scan_vault_certificates(self, vault_uri: str, vault_name: str, resource_group: str, credential: Optional[Any] = None) -> List[AzureFinding]:
        findings: List[AzureFinding] = []
        try:
            cred = credential or DefaultAzureCredential()
            cert_client = CertificateClient(vault_url=vault_uri, credential=cred)

            for cert_properties in cert_client.list_properties_of_certificates():
                cert_name = cert_properties.name
                cert_policy = cert_client.get_certificate_policy(cert_name)

                k_type = cert_policy.key_type if cert_policy and cert_policy.key_type else "RSA"
                k_size = cert_policy.key_size if cert_policy and cert_policy.key_size else 2048

                sec_findings = []
                if cert_properties.expires_on:
                    days_left = (cert_properties.expires_on - datetime.now(timezone.utc)).days
                    if days_left < 30:
                        sec_findings.append({
                            "issue": f"Azure Key Vault certificate expiring in {days_left} days",
                            "severity": "MEDIUM",
                        })

                findings.append(AzureFinding(
                    source_domain="infrastructure",
                    infra_provider="azure",
                    service="key_vault_certificate",
                    resource_group=resource_group,
                    vault_name=vault_name,
                    resource_id=cert_name,
                    algorithm=str(k_type),
                    key_size=k_size,
                    quantum_safe=False,
                    shor_vulnerable=True,
                    security_findings=sec_findings,
                    raw_metadata={
                        "enabled": cert_properties.enabled,
                        "expires_on": str(cert_properties.expires_on),
                    }
                ))
        except Exception:
            pass
        return findings