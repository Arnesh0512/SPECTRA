"""
crypto_recon.engine.normalizer
==============================
Normalizes heterogeneous cryptographic findings from source, artifacts,
infrastructure, and network scanners into a canonical data model.
"""

from dataclasses import dataclass, field
import hashlib
from typing import Any, Dict, List, Optional
import uuid
from pathlib import Path


@dataclass
class NormalizedCryptoAsset:
    """Canonical representation of a discovered cryptographic asset."""
    asset_id: str
    name: str
    asset_type: str  # algorithm, certificate, key, protocol
    source_domain: str  # source_code, artifacts, infrastructure, network
    location: str
    algorithm: str
    primitive: str
    key_size: Optional[int] = None
    mode: Optional[str] = None
    padding: Optional[str] = None
    curve: Optional[str] = None
    quantum_safe: bool = False
    shor_vulnerable: bool = True
    nist_status: str = "unknown"
    security_findings: List[Dict[str, str]] = field(default_factory=list)
    raw_metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "asset_id": self.asset_id,
            "name": self.name,
            "asset_type": self.asset_type,
            "source_domain": self.source_domain,
            "location": self.location,
            "algorithm": self.algorithm,
            "primitive": self.primitive,
            "key_size": self.key_size,
            "mode": self.mode,
            "padding": self.padding,
            "curve": self.curve,
            "quantum_safe": self.quantum_safe,
            "shor_vulnerable": self.shor_vulnerable,
            "nist_status": self.nist_status,
            "security_findings": self.security_findings,
            "raw_metadata": self.raw_metadata,
        }


class AssetNormalizer:
    """Standardizes disparate scanner findings into canonical cryptographic assets."""

    def normalize(self, raw_finding: Dict[str, Any]) -> NormalizedCryptoAsset:
        domain = raw_finding.get("source_domain", "unknown")

        if domain == "source_code":
            return self._normalize_source(raw_finding)
        elif domain == "artifacts":
            return self._normalize_artifact(raw_finding)
        elif domain == "infrastructure":
            return self._normalize_infrastructure(raw_finding)
        elif domain == "network":
            return self._normalize_network(raw_finding)

        return self._normalize_fallback(raw_finding)

    def normalize_batch(self, raw_findings: List[Dict[str, Any]]) -> List[NormalizedCryptoAsset]:
        return [self.normalize(f) for f in raw_findings]

    def _normalize_source(self, finding: Dict[str, Any]) -> NormalizedCryptoAsset:
        file_path = finding.get("file_path", "")
        line = finding.get("line_number", 0)
        algo = finding.get("algorithm", "unknown").upper()
        primitive = finding.get("primitive", "symmetric_cipher")
        mode = finding.get("mode")
        padding = finding.get("padding")
        key_size = finding.get("key_size")

        name = f"{algo}-{mode}" if mode else algo
        location = f"{file_path}:{line}"
        asset_id = self._generate_id("src", location, algo)

        return NormalizedCryptoAsset(
            asset_id=asset_id,
            name=name,
            asset_type="algorithm",
            source_domain="source_code",
            location=location,
            algorithm=algo,
            primitive=primitive,
            key_size=key_size,
            mode=mode,
            padding=padding,
            quantum_safe=finding.get("quantum_safe", False),
            shor_vulnerable=not finding.get("quantum_safe", False),
            nist_status=finding.get("nist_status", "unknown"),
            security_findings=finding.get("security_findings", []),
            raw_metadata=finding.get("raw_metadata", {}),
        )

    def _normalize_artifact(self, finding: Dict[str, Any]) -> NormalizedCryptoAsset:
        artifact_type = finding.get("artifact_type", "unknown")
        file_path = finding.get("file_path", "")

        if artifact_type == "x509_certificate":
            algo = finding.get("public_key_algorithm", "RSA")
            key_size = finding.get("key_size")
            name = f"Certificate ({finding.get('subject', 'unnamed')})"
            asset_id = self._generate_id("cert", file_path, finding.get("serial_number", ""))

            return NormalizedCryptoAsset(
                asset_id=asset_id,
                name=name,
                asset_type="certificate",
                source_domain="artifacts",
                location=file_path,
                algorithm=algo,
                primitive="asymmetric_signing",
                key_size=key_size,
                quantum_safe=finding.get("quantum_safe", False),
                shor_vulnerable=finding.get("shor_vulnerable", True),
                nist_status="legacy_approved",
                security_findings=finding.get("security_findings", []),
                raw_metadata=finding.get("raw_metadata", {}),
            )

        elif artifact_type == "compiled_binary":
            algos = finding.get("detected_algorithms", [])
            algo_str = ", ".join(algos) if algos else "Binary-Crypto-Imports"
            asset_id = self._generate_id("bin", file_path, algo_str)

            return NormalizedCryptoAsset(
                asset_id=asset_id,
                name=f"Binary Crypto ({Path(file_path).name})",
                asset_type="key" if "key" in algo_str.lower() else "algorithm",
                source_domain="artifacts",
                location=file_path,
                algorithm=algo_str,
                primitive="multiple",
                quantum_safe=finding.get("quantum_safe", False),
                shor_vulnerable=not finding.get("quantum_safe", False),
                nist_status="mixed",
                security_findings=finding.get("security_findings", []),
                raw_metadata=finding.get("raw_metadata", {}),
            )

        elif artifact_type == "container_definition":
            line = finding.get("line_number", 1)
            location = f"{file_path}:{line}"
            category = finding.get("finding_category", "container_crypto")
            algo = finding.get("algorithm", "Embedded-Crypto")
            asset_id = self._generate_id("container", location, category)

            return NormalizedCryptoAsset(
                asset_id=asset_id,
                name=f"Container Crypto Artifact ({category})",
                asset_type="key" if "key" in category else "algorithm",
                source_domain="artifacts",
                location=location,
                algorithm=algo,
                primitive="container_artifact",
                quantum_safe=finding.get("quantum_safe", False),
                shor_vulnerable=finding.get("shor_vulnerable", True),
                nist_status="unknown",
                security_findings=finding.get("security_findings", []),
                raw_metadata=finding.get("raw_metadata", {}),
            )

        return self._normalize_fallback(finding)

    def _normalize_infrastructure(self, finding: Dict[str, Any]) -> NormalizedCryptoAsset:
        provider = finding.get("infra_provider", "infrastructure")
        algo = finding.get("algorithm", "unknown")
        key_size = finding.get("key_size")

        if provider == "aws":
            service = finding.get("service", "kms")
            res_id = finding.get("resource_id", "arn")
            arn = finding.get("resource_arn", res_id)
            asset_type = "key" if service == "kms" else "certificate"
            asset_id = self._generate_id("aws", arn, algo)

            return NormalizedCryptoAsset(
                asset_id=asset_id,
                name=f"AWS {service.upper()} ({res_id})",
                asset_type=asset_type,
                source_domain="infrastructure",
                location=arn,
                algorithm=algo,
                primitive="key_management" if service == "kms" else "public_key_encryption",
                key_size=key_size,
                quantum_safe=finding.get("quantum_safe", False),
                shor_vulnerable=finding.get("shor_vulnerable", True),
                nist_status="approved",
                security_findings=finding.get("security_findings", []),
                raw_metadata=finding.get("raw_metadata", {}),
            )

        elif provider in ["terraform", "iac_manifest", "kubernetes", "cloudformation"]:
            f_path = finding.get("file_path", "")
            line = finding.get("line_number", 1)
            res_type = finding.get("resource_type") or finding.get("resource_kind", "resource")
            res_name = finding.get("resource_name", "unnamed")
            location = f"{f_path}:{line}"
            asset_id = self._generate_id("iac", location, f"{res_type}:{res_name}")

            return NormalizedCryptoAsset(
                asset_id=asset_id,
                name=f"IaC {res_type} ({res_name})",
                asset_type="key" if "key" in res_type.lower() else "certificate",
                source_domain="infrastructure",
                location=location,
                algorithm=algo,
                primitive="iac_declaration",
                key_size=key_size,
                quantum_safe=finding.get("quantum_safe", False),
                shor_vulnerable=finding.get("shor_vulnerable", True),
                nist_status="unknown",
                security_findings=finding.get("security_findings", []),
                raw_metadata=finding.get("raw_metadata", {}),
            )

        elif provider == "hardware":
            dev_type = finding.get("device_type", "hardware")
            dev_name = finding.get("device_name", "Hardware Module")
            asset_id = self._generate_id("hw", dev_type, dev_name)

            return NormalizedCryptoAsset(
                asset_id=asset_id,
                name=dev_name,
                asset_type="key" if dev_type in ["tpm", "hsm"] else "algorithm",
                source_domain="infrastructure",
                location=f"hardware://{dev_type}/{dev_name}",
                algorithm=algo,
                primitive="hardware_security_module",
                quantum_safe=finding.get("quantum_safe", False),
                shor_vulnerable=finding.get("shor_vulnerable", True),
                nist_status="hardware_certified",
                security_findings=finding.get("security_findings", []),
                raw_metadata=finding.get("raw_metadata", {}),
            )

        return self._normalize_fallback(finding)

    def _normalize_network(self, finding: Dict[str, Any]) -> NormalizedCryptoAsset:
        target = finding.get("target") or finding.get("file_path", "endpoint")
        port = finding.get("port") or finding.get("listen_port", 443)
        location = f"{target}:{port}"

        if "cipher_suite" in finding:
            # Active TLS Handshake
            cipher = finding.get("cipher_suite", "unknown")
            tls_ver = finding.get("tls_version", "unknown")
            asset_id = self._generate_id("net", location, cipher)

            return NormalizedCryptoAsset(
                asset_id=asset_id,
                name=f"TLS Session ({location})",
                asset_type="protocol",
                source_domain="network",
                location=location,
                algorithm=cipher,
                primitive="key_exchange_and_transport",
                key_size=finding.get("cert_key_size"),
                quantum_safe=finding.get("quantum_safe", False),
                shor_vulnerable=finding.get("shor_vulnerable", True),
                nist_status="approved" if tls_ver in ["TLSv1.2", "TLSv1.3"] else "deprecated",
                security_findings=finding.get("security_findings", []),
                raw_metadata=finding.get("raw_metadata", {}),
            )

        elif finding.get("config_type") == "nginx":
            # Nginx config
            ciphers = finding.get("ciphers") or "DEFAULT"
            server_name = finding.get("server_name", "default")
            f_path = finding.get("file_path", "")
            line = finding.get("line_number", 1)
            loc = f"{f_path}:{line}"
            asset_id = self._generate_id("nginx", loc, server_name)

            return NormalizedCryptoAsset(
                asset_id=asset_id,
                name=f"Nginx SSL Host ({server_name})",
                asset_type="protocol",
                source_domain="network",
                location=loc,
                algorithm=ciphers,
                primitive="tls_proxy_termination",
                quantum_safe=finding.get("quantum_safe", False),
                shor_vulnerable=finding.get("shor_vulnerable", True),
                nist_status="configurable",
                security_findings=finding.get("security_findings", []),
                raw_metadata=finding.get("raw_metadata", {}),
            )

        elif finding.get("protocol") == "ssh":
            # SSH protocol config
            f_path = finding.get("file_path", "")
            asset_id = self._generate_id("ssh", f_path, "sshd")

            return NormalizedCryptoAsset(
                asset_id=asset_id,
                name="SSH Daemon Cryptographic Configuration",
                asset_type="protocol",
                source_domain="network",
                location=f_path,
                algorithm="SSH-Transport",
                primitive="secure_shell_transport",
                quantum_safe=finding.get("quantum_safe", False),
                shor_vulnerable=finding.get("shor_vulnerable", True),
                nist_status="approved",
                security_findings=finding.get("security_findings", []),
                raw_metadata=finding.get("raw_metadata", {}),
            )

        return self._normalize_fallback(finding)

    def _normalize_fallback(self, finding: Dict[str, Any]) -> NormalizedCryptoAsset:
        algo = finding.get("algorithm", "UNKNOWN")
        loc = finding.get("file_path") or finding.get("location") or str(uuid.uuid4())
        asset_id = self._generate_id("gen", loc, algo)

        return NormalizedCryptoAsset(
            asset_id=asset_id,
            name=f"Cryptographic Asset ({algo})",
            asset_type="algorithm",
            source_domain=finding.get("source_domain", "unknown"),
            location=loc,
            algorithm=algo,
            primitive="cryptographic_operation",
            quantum_safe=finding.get("quantum_safe", False),
            shor_vulnerable=finding.get("shor_vulnerable", True),
            nist_status="unknown",
            security_findings=finding.get("security_findings", []),
            raw_metadata=finding.get("raw_metadata", {}),
        )

    def _generate_id(self, prefix: str, location: str, differentiator: str) -> str:
        """Generates a deterministic unique asset ID via SHA-256 hash."""
        seed = f"{prefix}:{location}:{differentiator}".encode("utf-8")
        digest = hashlib.sha256(seed).hexdigest()[:16]
        return f"{prefix}-{digest}"