"""
spectra.scanners.source.rust_scanner
====================================
Rust source code cryptographic scanner.
Inspects ring, aes_gcm, rsa, and rustls crates in .rs files.
"""

from pathlib import Path
import re
from typing import List

from .base import BaseSourceScanner, SourceFinding
from .rules import RuleEngine


RUST_CALL_REGEX = re.compile(
    r'\b(?P<class>Aes128Gcm|Aes256Gcm|RsaPrivateKey|aead::AES_256_GCM|aead::CHACHA20_POLY1305)::(?P<method>new|generate|new_with_rng)\b'
)


class RustScanner(BaseSourceScanner):
    """Scanner for Rust source files."""

    def supported_extensions(self) -> List[str]:
        return [".rs"]

    def parse_file(self, file_path: Path) -> List[SourceFinding]:
        findings: List[SourceFinding] = []
        try:
            with open(file_path, "r", encoding="utf-8", errors="replace") as f:
                lines = f.readlines()
        except Exception:
            return []

        for line_idx, line in enumerate(lines, start=1):
            for match in RUST_CALL_REGEX.finditer(line):
                cls = match.group("class")
                method = match.group("method")
                col = match.start()

                algo_rule = None
                cls_lower = cls.lower()
                if "aes" in cls_lower:
                    algo_rule = self.rule_engine.algorithms.get("ALGO-AES")
                elif "rsa" in cls_lower:
                    algo_rule = self.rule_engine.algorithms.get("ALGO-RSA")
                elif "chacha" in cls_lower:
                    algo_rule = self.rule_engine.algorithms.get("ALGO-CHACHA20-POLY1305")

                snippet = self.extract_snippet(file_path, line_idx)
                findings.append(SourceFinding(
                    source_domain="source_code",
                    language="rust",
                    file_path=str(file_path.resolve()),
                    line_number=line_idx,
                    column_number=col,
                    code_snippet=snippet,
                    primitive=algo_rule.primitive if algo_rule else "cryptographic_operation",
                    algorithm=algo_rule.name if algo_rule else cls,
                    quantum_safe=algo_rule.quantum_safe if algo_rule else False,
                    nist_status=algo_rule.nist_status if algo_rule else "unknown",
                    security_findings=[],
                    raw_metadata={"rust_call": f"{cls}::{method}"}
                ))

        return findings