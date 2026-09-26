"""
spectra.scanners.source.go_scanner
==================================
Go source code cryptographic scanner.
Inspects crypto/* packages and golang.org/x/crypto calls in .go files.
"""

from pathlib import Path
import re
from typing import List

from .base import BaseSourceScanner, SourceFinding
from .rules import RuleEngine


GO_CALL_REGEX = re.compile(
    r'\b(?P<pkg>aes|des|rsa|ecdsa|sha256|sha512|md5)\.(?P<method>NewCipher|NewTripleDESCipher|GenerateKey|New)\b'
)


class GoScanner(BaseSourceScanner):
    """Scanner for Go source files."""

    def supported_extensions(self) -> List[str]:
        return [".go"]

    def parse_file(self, file_path: Path) -> List[SourceFinding]:
        findings: List[SourceFinding] = []
        try:
            with open(file_path, "r", encoding="utf-8", errors="replace") as f:
                lines = f.readlines()
        except Exception:
            return []

        algo_map = {
            "aes": "ALGO-AES",
            "des": "ALGO-DES",
            "rsa": "ALGO-RSA",
            "ecdsa": "ALGO-ECDSA",
            "sha256": "ALGO-SHA2-256",
            "sha512": "ALGO-SHA2-512",
            "md5": "ALGO-MD5"
        }

        for line_idx, line in enumerate(lines, start=1):
            for match in GO_CALL_REGEX.finditer(line):
                pkg = match.group("pkg").lower()
                method = match.group("method")
                col = match.start()

                algo_id = algo_map.get(pkg)
                if method == "NewTripleDESCipher":
                    algo_id = "ALGO-3DES"

                algo_rule = self.rule_engine.algorithms.get(algo_id) if algo_id else None

                sec_findings = []
                if pkg in ["des", "md5"] or method == "NewTripleDESCipher":
                    sec_findings.append({
                        "issue": f"Deprecated Go crypto API invoked: crypto/{pkg}.{method}",
                        "severity": "HIGH"
                    })

                snippet = self.extract_snippet(file_path, line_idx)
                findings.append(SourceFinding(
                    source_domain="source_code",
                    language="go",
                    file_path=str(file_path.resolve()),
                    line_number=line_idx,
                    column_number=col,
                    code_snippet=snippet,
                    primitive=algo_rule.primitive if algo_rule else "cryptographic_operation",
                    algorithm=algo_rule.name if algo_rule else pkg.upper(),
                    quantum_safe=algo_rule.quantum_safe if algo_rule else False,
                    nist_status=algo_rule.nist_status if algo_rule else "unknown",
                    security_findings=sec_findings,
                    raw_metadata={"go_call": f"{pkg}.{method}"}
                ))

        return findings