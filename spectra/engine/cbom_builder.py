"""
spectra.engine.cbom_builder
================================
Builds compliant CycloneDX 1.6 Cryptographic Bill of Materials (CBOM) documents
incorporating cryptoProperties, cross-domain dependencies, and Mosca quantum assessments.
"""

from datetime import datetime, timezone
import json
from pathlib import Path
from typing import Any, Dict, List, Optional
import uuid

from .correlator import CorrelatedAsset
from .mosca import MoscaEvaluation


CYCLONEDX_VERSION = "1.6"
CBOM_SCHEMA_VERSION = "http://cyclonedx.org/schema/bom-1.6.schema.json"


class CBOMBuilder:
    """Constructs a CycloneDX 1.6 CBOM document from correlated assets and Mosca assessments."""

    def __init__(self, application_name: str = "crypto-recon-target", version: str = "1.0.0"):
        self.application_name = application_name
        self.version = version

    def build_cbom(
        self,
        correlated_assets: List[CorrelatedAsset],
        mosca_evaluations: Dict[str, MoscaEvaluation],
    ) -> Dict[str, Any]:
        """Generates the full CycloneDX 1.6 JSON dictionary."""
        serial_uuid = f"urn:uuid:{uuid.uuid4()}"
        timestamp = datetime.now(timezone.utc).isoformat()

        bom: Dict[str, Any] = {
            "$schema": CBOM_SCHEMA_VERSION,
            "bomFormat": "CycloneDX",
            "specVersion": CYCLONEDX_VERSION,
            "serialNumber": serial_uuid,
            "version": 1,
            "metadata": {
                "timestamp": timestamp,
                "tools": {
                    "components": [
                        {
                            "type": "application",
                            "name": "crypto-recon",
                            "version": "1.0.0",
                            "description": "Enterprise Multi-Domain Cryptographic Inventory and CBOM Engine",
                        }
                    ]
                },
                "component": {
                    "type": "application",
                    "name": self.application_name,
                    "version": self.version,
                },
            },
            "components": [],
            "dependencies": [],
            "vulnerabilities": [],
        }

        for item in correlated_assets:
            asset = item.primary_asset
            mosca = mosca_evaluations.get(asset.asset_id)
            bom_ref = f"crypto-ref-{asset.asset_id}"

            # 1. Build CycloneDX 1.6 Component
            component = self._build_crypto_component(bom_ref, asset, mosca)
            bom["components"].append(component)

            # 2. Build Dependency Linkage
            dep_block = {
                "ref": bom_ref,
                "dependsOn": [f"crypto-ref-{rel_id}" for rel_id in item.related_asset_ids],
            }
            bom["dependencies"].append(dep_block)

            # 3. Add Vulnerability Entries
            vulns = self._build_vulnerability_entries(bom_ref, asset, mosca)
            bom["vulnerabilities"].extend(vulns)

        return bom

    def save_cbom(
        self,
        cbom_dict: Dict[str, Any],
        output_file: Path,
        indent: int = 2,
    ) -> Path:
        """Writes CBOM JSON to disk."""
        output_file.parent.mkdir(parents=True, exist_ok=True)
        with open(output_file, "w", encoding="utf-8") as f:
            json.dump(cbom_dict, f, indent=indent)
        return output_file

    def _build_crypto_component(
        self,
        bom_ref: str,
        asset: Any,
        mosca: Optional[MoscaEvaluation],
    ) -> Dict[str, Any]:
        """Constructs a component with CycloneDX 1.6 cryptoProperties."""
        component_type = "cryptographic-asset"

        crypto_prop: Dict[str, Any] = {
            "assetType": asset.asset_type,
            "algorithmProperties": {
                "primitive": asset.primitive,
                "parameterSetIdentifier": asset.algorithm,
                "executionEnvironment": asset.source_domain,
                "implementationPlatform": "cross-platform",
            },
            "detectionContext": {
                "line": asset.location,
            },
        }

        # Key / Mode / Curve / Padding attributes
        if asset.key_size:
            crypto_prop["algorithmProperties"]["keyLength"] = asset.key_size
        if asset.mode:
            crypto_prop["algorithmProperties"]["mode"] = asset.mode
        if asset.padding:
            crypto_prop["algorithmProperties"]["padding"] = asset.padding
        if asset.curve:
            crypto_prop["algorithmProperties"]["curve"] = asset.curve

        # Quantum risk & NIST metadata
        crypto_prop["properties"] = [
            {"name": "crypto:quantumSafe", "value": str(asset.quantum_safe).lower()},
            {"name": "crypto:shorVulnerable", "value": str(asset.shor_vulnerable).lower()},
            {"name": "crypto:nistStatus", "value": str(asset.nist_status)},
        ]

        # Ingest scanner context (language, operation)
        if hasattr(asset, "raw_metadata") and isinstance(asset.raw_metadata, dict):
            if "language" in asset.raw_metadata:
                crypto_prop["properties"].append(
                    {"name": "crypto:sourceLanguage", "value": str(asset.raw_metadata["language"])}
                )
            if "operation" in asset.raw_metadata:
                crypto_prop["properties"].append(
                    {"name": "crypto:operation", "value": str(asset.raw_metadata["operation"])}
                )

        if mosca:
            crypto_prop["properties"].extend([
                {"name": "mosca:riskLevel", "value": mosca.risk_level},
                {"name": "mosca:inequalityBreached", "value": str(mosca.is_inequality_breached).lower()},
                {"name": "mosca:shelfLifeX", "value": str(mosca.shelf_life_x)},
                {"name": "mosca:migrationTimeY", "value": str(mosca.migration_time_y)},
                {"name": "mosca:quantumThresholdZ", "value": str(mosca.quantum_threshold_z)},
                {"name": "mosca:sndlVulnerable", "value": str(mosca.sndl_vulnerable).lower()},
                {"name": "mosca:recommendedPQC", "value": mosca.recommended_pqc_replacement},
            ])

        return {
            "bom-ref": bom_ref,
            "type": component_type,
            "name": asset.name,
            "cryptoProperties": crypto_prop,
        }

    def _build_vulnerability_entries(
        self,
        bom_ref: str,
        asset: Any,
        mosca: Optional[MoscaEvaluation],
    ) -> List[Dict[str, Any]]:
        """Maps discovered security issues into CycloneDX vulnerabilities."""
        vulns: List[Dict[str, Any]] = []

        # Map static scanner findings
        for idx, finding in enumerate(asset.security_findings):
            vuln_id = f"CRYPTO-VULN-{asset.asset_id}-{idx+1}"
            vulns.append({
                "id": vuln_id,
                "source": {"name": "crypto-recon"},
                "ratings": [{
                    "severity": finding.get("severity", "MEDIUM").lower(),
                    "method": "other",
                }],
                "description": finding.get("issue", "Cryptographic compliance violation"),
                "affects": [{"ref": bom_ref}],
            })

        # Add Mosca quantum vulnerability entry if breached
        if mosca and mosca.is_inequality_breached:
            vulns.append({
                "id": f"MOSCA-PQC-EXP-{asset.asset_id}",
                "source": {"name": "Mosca-Theorem-Engine"},
                "ratings": [{
                    "severity": mosca.risk_level.lower(),
                    "method": "other",
                }],
                "description": mosca.rationale,
                "recommendation": f"Migrate to: {mosca.recommended_pqc_replacement}",
                "affects": [{"ref": bom_ref}],
            })

        return vulns