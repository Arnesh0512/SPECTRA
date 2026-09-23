"""
spectra.engine
===================
Core pipeline processing engine for cryptographic asset normalization,
cross-domain correlation, Mosca quantum risk analysis, and CycloneDX 1.6
Cryptographic Bill of Materials (CBOM) document generation.
"""

from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from spectra.config import ScanConfig
from spectra.utils.logger import log_header, log_info, log_step

from .cbom_builder import CBOMBuilder
from .correlator import AssetCorrelator, CorrelatedAsset
from .mosca import MoscaEvaluation, MoscaRiskEngine
from .normalizer import AssetNormalizer, NormalizedCryptoAsset


class CryptoAnalysisEngine:
    """Coordinates normalization, correlation, Mosca risk analysis, and CBOM production."""

    def __init__(self, config: ScanConfig):
        self.config = config
        self.normalizer = AssetNormalizer()
        self.correlator = AssetCorrelator()
        self.mosca_engine = MoscaRiskEngine()
        self.cbom_builder = CBOMBuilder()

    def process(
        self,
        raw_findings: List[Dict[str, Any]],
        output_file: Optional[Path] = None,
    ) -> Tuple[Dict[str, Any], List[CorrelatedAsset], Dict[str, MoscaEvaluation]]:
        """
        Executes the analysis pipeline on raw scanner findings.

        :param raw_findings: Consolidated raw findings from all scanners.
        :param output_file: Target path to write CycloneDX 1.6 CBOM JSON.
        :return: Tuple of (cbom_document_dict, correlated_assets, mosca_evaluations).
        """
        log_header("Beginning Cryptographic Analysis & CBOM Synthesis Pipeline")

        # 1. Normalization
        log_step(f"Step 1/4: Normalizing {len(raw_findings)} raw findings into canonical asset schema")
        normalized_assets: List[NormalizedCryptoAsset] = self.normalizer.normalize_batch(raw_findings)
        log_info(f"Successfully normalized {len(normalized_assets)} cryptographic asset(s).")

        # 2. Cross-Domain Correlation & Deduplication
        log_step("Step 2/4: Correlating assets across code, artifacts, infrastructure, and network")
        correlated_assets: List[CorrelatedAsset] = self.correlator.correlate(normalized_assets)
        correlated_links = sum(len(ca.cross_domain_links) for ca in correlated_assets)
        log_info(f"Established {correlated_links} cross-domain relationship link(s) across {len(correlated_assets)} composite assets.")

        # 3. Mosca Quantum Risk Evaluation
        log_step("Step 3/4: Evaluating Mosca Theorem (X + Y > Z) and quantum exposure horizons")
        mosca_evals: Dict[str, MoscaEvaluation] = self.mosca_engine.evaluate_batch(normalized_assets)
        breached_count = sum(1 for m in mosca_evals.values() if m.is_inequality_breached)
        log_info(f"Identified {breached_count} asset(s) breaching Mosca's inequality threshold.")

        # 4. CycloneDX 1.6 CBOM Generation
        log_step("Step 4/4: Constructing CycloneDX 1.6 CBOM document")
        cbom: Dict[str, Any] = self.cbom_builder.build_cbom(
            correlated_assets=correlated_assets,
            mosca_evaluations=mosca_evals,
        )

        if output_file:
            written_path = self.cbom_builder.save_cbom(cbom, output_file)
            log_info(f"CBOM JSON exported to: {written_path}")

        log_header("Cryptographic Pipeline Execution Complete")
        return cbom, correlated_assets, mosca_evals


__all__ = [
    "AssetNormalizer",
    "NormalizedCryptoAsset",
    "AssetCorrelator",
    "CorrelatedAsset",
    "MoscaRiskEngine",
    "MoscaEvaluation",
    "CBOMBuilder",
    "CryptoAnalysisEngine",
]