"""
crypto_recon.engine.mosca
=========================
Quantum risk evaluation engine applying Michele Mosca's Theorem:
If (X + Y > Z), the system is vulnerable to quantum compromise before
post-quantum remediation can be completed.
"""

from dataclasses import dataclass
from typing import Dict, List, Optional
from datetime import datetime

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


# Industry consensus default estimates (in years)
DEFAULT_CRQC_TARGET_YEAR = 2033  # Consensus target for CRQC risk models
DEFAULT_SHELF_LIFE_YEARS = 7     # Typical enterprise data retention horizon
DEFAULT_MIGRATION_YEARS = 3      # Typical migration timeline for systems


# PQC Algorithm standard recommendations
PQC_MAPPING = {
    "RSA": "ML-KEM-768 (FIPS 203) or ML-DSA-65 (FIPS 204)",
    "ECDSA": "ML-DSA-65 (FIPS 204) or SLH-DSA-SHA2-128s (FIPS 205)",
    "ECC": "ML-KEM-768 (FIPS 203) or ML-DSA-65 (FIPS 204)",
    "ECDH": "ML-KEM-768 (FIPS 203)",
    "ECDHE": "X25519MLKEM768 (Hybrid Post-Quantum)",
    "DSA": "ML-DSA-65 (FIPS 204)",
    "ED25519": "ML-DSA-65 (FIPS 204) or SLH-DSA-128s (FIPS 205)",
    "AES-128": "AES-256 (Grover quantum search resistance)",
    "AES-192": "AES-256",
}


class MoscaRiskEngine:
    """Evaluates quantum risk exposure across cryptographic assets using Mosca's inequality."""

    def __init__(
        self,
        target_crqc_year: int = DEFAULT_CRQC_TARGET_YEAR,
        default_shelf_life: int = DEFAULT_SHELF_LIFE_YEARS,
        default_migration_time: int = DEFAULT_MIGRATION_YEARS,
    ):
        self.target_crqc_year = target_crqc_year
        self.default_shelf_life = default_shelf_life
        self.default_migration_time = default_migration_time

    def evaluate_asset(self, asset: NormalizedCryptoAsset) -> MoscaEvaluation:
        """Applies Mosca's theorem to a single normalized crypto asset."""
        current_year = datetime.now().year
        z = max(1, self.target_crqc_year - current_year)
        x = self.default_shelf_life
        y = self.default_migration_time

        # Quantum-safe assets bypass inequality
        if asset.quantum_safe or not asset.shor_vulnerable:
            return MoscaEvaluation(
                asset_id=asset.asset_id,
                algorithm=asset.algorithm,
                shelf_life_x=x,
                migration_time_y=0,
                quantum_threshold_z=z,
                is_inequality_breached=False,
                risk_level="QUANTUM_SAFE",
                sndl_vulnerable=False,
                recommended_pqc_replacement="None (Already Post-Quantum or Grover-Resistant)",
                rationale="Asset is inherently quantum-resistant or utilizes NIST-approved PQC primitives."
            )

        # Classical asymmetric primitives are vulnerable to Shor's algorithm
        breached = (x + y) > z
        sndl = asset.primitive in [
            "public_key_encryption",
            "key_exchange_and_transport",
            "key_management",
            "asymmetric_encryption"
        ]

        if breached and sndl:
            risk = "CRITICAL"
            rationale = (
                f"Mosca inequality breached ({x} + {y} > {z}). Asset is vulnerable to "
                "Store-Now-Decrypt-Later (SNDL) attacks. Classical key exchange or encryption "
                "can be recorded now and decrypted once a CRQC is realized."
            )
        elif breached:
            risk = "HIGH"
            rationale = (
                f"Mosca inequality breached ({x} + {y} > {z}). Asset authentication or signatures "
                "will fail quantum integrity checks before migration can be completed."
            )
        else:
            risk = "MEDIUM"
            rationale = (
                f"Mosca inequality currently holds ({x} + {y} <= {z}), but proactive migration "
                "to post-quantum algorithms must begin to prevent future breach."
            )

        # Determine replacement algorithm
        replacement = "ML-KEM-768 / ML-DSA-65"
        for k, v in PQC_MAPPING.items():
            if k in asset.algorithm.upper():
                replacement = v
                break

        return MoscaEvaluation(
            asset_id=asset.asset_id,
            algorithm=asset.algorithm,
            shelf_life_x=x,
            migration_time_y=y,
            quantum_threshold_z=z,
            is_inequality_breached=breached,
            risk_level=risk,
            sndl_vulnerable=sndl,
            recommended_pqc_replacement=replacement,
            rationale=rationale
        )

    def evaluate_batch(self, assets: List[NormalizedCryptoAsset]) -> Dict[str, MoscaEvaluation]:
        """Evaluates a collection of normalized assets, keyed by asset_id."""
        return {asset.asset_id: self.evaluate_asset(asset) for asset in assets}