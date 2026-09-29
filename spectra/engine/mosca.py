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
import math
import fnmatch

from .normalizer import NormalizedCryptoAsset


@dataclass
class MoscaEvaluation:
    """Quantum exposure metrics and Mosca inequality calculation for an asset."""
    asset_id: str
    algorithm: str
    shelf_life_x: int
    migration_time_y: float
    quantum_threshold_z: int
    is_inequality_breached: bool
    risk_level: str
    sndl_vulnerable: bool
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


def parse_gitignore(target_dir: Path) -> List[str]:
    """Parses .gitignore patterns if present."""
    patterns = []
    gitignore_path = target_dir / ".gitignore"
    if gitignore_path.is_file():
        try:
            with open(gitignore_path, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith("#"):
                        patterns.append(line)
        except Exception:
            pass
    return patterns


def is_ignored(path: Path, target_dir: Path, gitignore_patterns: List[str], excluded_dirs: set) -> bool:
    """Checks if a file matches .gitignore or standard exclusion directories."""
    try:
        rel_path = path.relative_to(target_dir)
    except ValueError:
        return True

    for part in rel_path.parts:
        if part in excluded_dirs:
            return True

    rel_str = rel_path.as_posix()
    for pattern in gitignore_patterns:
        cleaned_pattern = pattern.rstrip("/")
        if fnmatch.fnmatch(rel_str, cleaned_pattern) or fnmatch.fnmatch(path.name, cleaned_pattern):
            return True
        if pattern.endswith("/") and any(fnmatch.fnmatch(p, cleaned_pattern) for p in rel_path.parts):
            return True

    return False


def count_codebase_loc(target_dir: Optional[Path], excluded_dirs: Optional[List[str]] = None) -> int:
    """
    Directly scans the target directory (ignoring .gitignore and library exclusions)
    to compute the true codebase-wide Lines of Code (LOC).
    """
    if not target_dir or not target_dir.exists():
        return 10000

    excluded = set(excluded_dirs or [
        ".git", "node_modules", "vendor", "target", "dist", 
        "build", ".venv", "venv", "__pycache__", ".tox", ".pytest_cache"
    ])
    
    gitignore_patterns = parse_gitignore(target_dir)
    source_extensions = {
        ".py", ".js", ".ts", ".jsx", ".tsx", ".java", ".kt", 
        ".go", ".rs", ".c", ".cpp", ".cc", ".h", ".hpp", ".tf", ".hcl"
    }

    total_loc = 0
    try:
        for path in target_dir.rglob("*"):
            if not path.is_file():
                continue
            if path.suffix.lower() not in source_extensions:
                continue
            if is_ignored(path, target_dir, gitignore_patterns, excluded):
                continue

            try:
                with open(path, "r", encoding="utf-8", errors="ignore") as f:
                    total_loc += sum(1 for _ in f)
            except Exception:
                pass
    except Exception:
        pass

    return max(1000, total_loc)


class MoscaRiskEngine:
    """Evaluates quantum risk exposure across cryptographic assets using Mosca's inequality and true codebase COCOMO scale."""

    def __init__(self, policy_file: Optional[Path] = None, staff_size: int = 6):
        if policy_file is None:
            policy_file = Path(__file__).resolve().parent.parent.parent / "cbom_policy.json"
        self.policy = self._load_policy(policy_file)
        
        scenarios = self.policy.get("crqc_arrival_scenarios", {"pessimistic": 2033})
        self.target_crqc_year = scenarios.get("pessimistic", 2033)
        self.default_shelf_life = 7
        self.algorithm_risks = self.policy.get("algorithm_risk_definitions", {})
        self.staff_size = max(1, staff_size)

    def _load_policy(self, path: Path) -> Dict[str, Any]:
        if not path.is_file():
            return {}
        try:
            with open(path, "r", encoding="utf-8") as f:
                return json.load(f) or {}
        except Exception:
            return {}

    def _calculate_cocomo_baseline_y(self, total_repository_loc: int) -> float:
        """
        Computes repository-wide baseline migration time using Basic COCOMO (Semi-detached mode):
        Effort (Person-Months) = 3.0 * (KLOC)^1.12
        Migration Time (Years) = Effort / (Staff Size * 12 months)
        """
        kloc = max(1.0, total_repository_loc / 1000.0)
        effort_person_months = 3.0 * (kloc ** 1.12)
        migration_years = effort_person_months / (self.staff_size * 12.0)
        return round(migration_years, 2)

    def _calculate_dynamic_y(self, asset: NormalizedCryptoAsset, total_repository_loc: int) -> float:
        cocomo_baseline = self._calculate_cocomo_baseline_y(total_repository_loc)

        w1 = 1.0
        w2 = 1.2
        w3 = 0.4
        dir_calls = asset.direct_calls
        trans_calls = asset.transitive_calls
        depth = max(1, asset.call_depth)

        local_multiplier = (w1 + (w2 * dir_calls) + (w3 * trans_calls * depth))
        if asset.is_upstream_dependency:
            local_multiplier *= 2.5

        # 2. Domain-specific adjustments (Infrastructure, Certificates, Network)
        domain_modifier = 1.0
        if asset.source_domain == "infrastructure":
            domain_modifier = 1.5
        elif asset.source_domain == "network":
            domain_modifier = 1.4

        blended_y = cocomo_baseline * 0.4 + (local_multiplier * domain_modifier * 0.6)
        return max(0.5, round(blended_y, 2))

    def evaluate_asset(self, asset: NormalizedCryptoAsset, total_repository_loc: int = 10000) -> MoscaEvaluation:
        current_year = datetime.now().year
        z = max(1, self.target_crqc_year - current_year)
        x = self.default_shelf_life
        y = self._calculate_dynamic_y(asset, total_repository_loc)

        if asset.quantum_safe or not asset.shor_vulnerable:
            return MoscaEvaluation(
                asset_id=asset.asset_id, algorithm=asset.algorithm,
                shelf_life_x=x, migration_time_y=0.0, quantum_threshold_z=z,
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

        # ENHANCEMENT 2: Guarded Mosca SNDL logic for Post-Quantum KEMs
        is_pqc_kem = any(pqc in algo_upper for pqc in ["ML-KEM", "KYBER", "ML-DSA", "DILITHIUM", "SLH-DSA"])
        sndl = (not is_pqc_kem) and any(ind in algo_upper for ind in ["ECDH", "DH", "RSA", "ECC", "X25519"])

        if breached and sndl:
            risk = "CRITICAL"
            rationale = f"Mosca inequality breached ({x} + {y} > {z}). Vulnerable to Store-Now-Decrypt-Later (SNDL) attacks across codebase scale."
        elif breached:
            risk = base_severity
            rationale = f"Mosca inequality breached ({x} + {y} > {z}). Codebase migration footprint requires proactive scheduling."
        else:
            risk = "MEDIUM"
            rationale = f"Mosca inequality currently holds ({x} + {y} <= {z})."

        return MoscaEvaluation(
            asset_id=asset.asset_id, algorithm=asset.algorithm,
            shelf_life_x=x, migration_time_y=y, quantum_threshold_z=z,
            is_inequality_breached=breached, risk_level=risk,
            sndl_vulnerable=sndl, recommended_pqc_replacement=replacement or "ML-KEM-768",
            rationale=rationale
        )

    def evaluate_batch(self, assets: List[NormalizedCryptoAsset], target_dir: Optional[Path] = None, excluded_dirs: Optional[List[str]] = None) -> Dict[str, MoscaEvaluation]:
        total_repo_loc = count_codebase_loc(target_dir, excluded_dirs)
        return {asset.asset_id: self.evaluate_asset(asset, total_repo_loc) for asset in assets}