"""
spectra.engine.correlator
==============================
Cross-domain cryptographic asset correlator and dependency graph generator.
Correlates findings across source code, disk artifacts, infrastructure/IaC,
and live network endpoints to create composite cryptographic asset links.
"""

from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Set

from .normalizer import NormalizedCryptoAsset


@dataclass
class CorrelatedAsset:
    """Represents a primary cryptographic asset linked to related cross-domain assets."""
    primary_asset: NormalizedCryptoAsset
    related_asset_ids: List[str] = field(default_factory=list)
    correlation_type: str = "standalone"  # standalone, cert_to_service, iac_to_cloud, code_to_runtime
    cross_domain_links: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict:
        return {
            "primary_asset": self.primary_asset.to_dict(),
            "related_asset_ids": self.related_asset_ids,
            "correlation_type": self.correlation_type,
            "cross_domain_links": self.cross_domain_links,
        }


class AssetCorrelator:
    """Correlates and deduplicates cryptographic findings across reconnaissance domains."""

    def correlate(self, assets: List[NormalizedCryptoAsset]) -> List[CorrelatedAsset]:
        """Correlates assets across domains and generates cross-layer relationship links."""
        correlated_results: List[CorrelatedAsset] = []
        consumed_ids: Set[str] = set()

        # Indexes for fast lookup
        cert_assets = [a for a in assets if a.asset_type == "certificate"]
        network_assets = [a for a in assets if a.source_domain == "network"]
        iac_assets = [a for a in assets if a.source_domain == "infrastructure" and "iac" in a.asset_id]
        cloud_assets = [a for a in assets if a.source_domain == "infrastructure" and "aws" in a.asset_id]

        # 1. Correlate Certificates with Network Web Servers / Endpoints
        for cert in cert_assets:
            cert_path = cert.location.lower()
            related_ids = []
            links = []

            for net_asset in network_assets:
                # Check Nginx config references
                ref_cert = net_asset.raw_metadata.get("certificate_path")
                if ref_cert and (Path(ref_cert).name.lower() in cert_path or cert_path in ref_cert.lower()):
                    related_ids.append(net_asset.asset_id)
                    links.append(f"Referenced by Nginx directive in {net_asset.location}")
                    consumed_ids.add(net_asset.asset_id)

                # Check live TLS endpoint certificate subject match
                endpoint_subj = net_asset.raw_metadata.get("cert_subject", "")
                cert_subj = cert.raw_metadata.get("subject", cert.name)
                if endpoint_subj and endpoint_subj in cert_subj:
                    related_ids.append(net_asset.asset_id)
                    links.append(f"Negotiated in live TLS connection on {net_asset.location}")
                    consumed_ids.add(net_asset.asset_id)

            if related_ids:
                consumed_ids.add(cert.asset_id)
                correlated_results.append(CorrelatedAsset(
                    primary_asset=cert,
                    related_asset_ids=related_ids,
                    correlation_type="cert_to_service",
                    cross_domain_links=links,
                ))

        # 2. Correlate IaC declarations with Cloud KMS / ACM instances
        for iac in iac_assets:
            res_name = iac.name.lower()
            related_ids = []
            links = []

            for cloud in cloud_assets:
                cloud_arn = cloud.location.lower()
                cloud_id = cloud.name.lower()
                if any(part in cloud_arn or part in cloud_id for part in res_name.split() if len(part) > 3):
                    related_ids.append(cloud.asset_id)
                    links.append(f"IaC definition provisioned as cloud resource {cloud.location}")
                    consumed_ids.add(cloud.asset_id)

            if related_ids:
                consumed_ids.add(iac.asset_id)
                correlated_results.append(CorrelatedAsset(
                    primary_asset=iac,
                    related_asset_ids=related_ids,
                    correlation_type="iac_to_cloud",
                    cross_domain_links=links,
                ))

        # 3. Add remaining non-correlated / standalone assets
        for asset in assets:
            if asset.asset_id not in consumed_ids:
                correlated_results.append(CorrelatedAsset(
                    primary_asset=asset,
                    related_asset_ids=[],
                    correlation_type="standalone",
                    cross_domain_links=[],
                ))

        return correlated_results