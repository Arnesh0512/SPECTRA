
"""
spectra.engine.mosca
=========================
Quantum risk evaluation engine applying Michele Mosca's Theorem:
If (X + Y > Z), the system is vulnerable to quantum compromise before
post-quantum remediation can be completed. Loaded via cbom_policy.json.
"""

from dataclasses import dataclass
from typing import Dict, List, Optional, Any
from datetime import datetime
from pathlib import Path
import json

from .normalizer import NormalizedCryptoAsset


@dataclass
class MoscaEvaluation:
    """Quantum exposure metrics and Mosca inequality calculation for an asset."""
    asset_id: str
    algorithm: str
    shelf_life_x: int  # Required confidentiality duration (years)
    migration_time_y: int  # Time needed to migrate to PQC (years)
    quantum_threshold_z: int  # Estimated years until CRQC viability
    is_inequality_breached: bool  # True if (X + Y > Z)
    risk_level: str  # CRITICAL, HIGH, MEDIUM, LOW, QUANTUM_SAFE
    sndl_vulnerable: bool  # Store Now, Decrypt Later susceptibility
    recommended_pqc_replacement: str
    rationale: str

    def to_dict(self) -> Dict:
        return {
            "asset_id": self.asset_id,
            "algorithm": self.algorithm,
            "shelf_life_x": self.shelf_life_x,
            "migration_time_y": self.migration_time_y,
            "quantum_threshold_z": self.quantum_threshold_z,
            "is_inequality_breached": self.is_inequality_breached,
            "risk_level": self.risk_level,
            "sndl_vulnerable": self.sndl_vulnerable,
            "recommended_pqc_replacement": self.recommended_pqc_replacement,
            "rationale": self.rationale,
        }


class MoscaRiskEngine:
    """Evaluates quantum risk exposure across cryptographic assets using Mosca's inequality and cbom_policy.json."""

    def __init__(self, policy_file: Optional[Path] = None):
        if policy_file is None:
            policy_file = Path(__file__).resolve().parent.parent.parent / "cbom_policy.json"
        self.policy = self._load_policy(policy_file)
        
        scenarios = self.policy.get("crqc_arrival_scenarios", {"pessimistic": 2033})
        self.target_crqc_year = scenarios.get("pessimistic", 2033)
        self.default_shelf_life = 7
        self.default_migration_time = 3
        self.algorithm_risks = self.policy.get("algorithm_risk_definitions", {})

    def _load_policy(self, path: Path) -> Dict[str, Any]:
        if not path.is_file():
            return {}
        try:
            with open(path, "r", encoding="utf-8") as f:
                return json.load(f) or {}
        except Exception:
            return {}

    def evaluate_asset(self, asset: NormalizedCryptoAsset) -> MoscaEvaluation:
        """Applies Mosca's theorem to a single normalized crypto asset."""
        current_year = datetime.now().year
        z = max(1, self.target_crqc_year - current_year)
        x = self.default_shelf_life
        y = self.default_migration_time

        if asset.quantum_safe or not asset.shor_vulnerable:
            return MoscaEvaluation(
                asset_id=asset.asset_id, algorithm=asset.algorithm,
                shelf_life_x=x, migration_time_y=0, quantum_threshold_z=z,
                is_inequality_breached=False, risk_level="QUANTUM_SAFE",
                sndl_vulnerable=False, recommended_pqc_replacement="None (Quantum Safe)",
                rationale="Asset is inherently quantum-resistant."
            )

        # Classical asymmetric primitives are vulnerable to Shor's algorithm
        breached = (x + y) > z
        algo_upper = asset.algorithm.upper()
        
        risk_def = self.algorithm_risks.get(algo_upper, {})
        base_severity = risk_def.get("severity", "HIGH")
        replacement = risk_def.get("replacement", "ML-KEM-768 / ML-DSA-65")

        sndl = any(ind in algo_upper for ind in ["ECDH", "DH", "RSA", "ECC", "X25519", "KEM", "KYBER"])

        if breached and sndl:
            risk = "CRITICAL"
            rationale = f"Mosca inequality breached ({x} + {y} > {z}). Vulnerable to Store-Now-Decrypt-Later (SNDL) attacks."
        elif breached:
            risk = base_severity
            rationale = f"Mosca inequality breached ({x} + {y} > {z}). Signatures or keys vulnerable before migration."
        else:
            risk = "MEDIUM"
            rationale = f"Mosca inequality currently holds ({x} + {y} <= {z}), but migration should be planned."

        return MoscaEvaluation(
            asset_id=asset.asset_id, algorithm=asset.algorithm,
            shelf_life_x=x, migration_time_y=y, quantum_threshold_z=z,
            is_inequality_breached=breached, risk_level=risk,
            sndl_vulnerable=sndl, recommended_pqc_replacement=replacement or "ML-KEM-768",
            rationale=rationale
        )

    def evaluate_batch(self, assets: List[NormalizedCryptoAsset]) -> Dict[str, MoscaEvaluation]:
        """Evaluates a collection of normalized assets, keyed by asset_id."""
        return {asset.asset_id: self.evaluate_asset(asset) for asset in assets}
