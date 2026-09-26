"""
spectra.scanners.source.cpp_scanner
===================================
C and C++ source code cryptographic scanner.
Inspects OpenSSL, BoringSSL, and libsodium invocations in .c, .cpp, .cc, and header files.
"""

from pathlib import Path
import re
from typing import List

from .base import BaseSourceScanner, SourceFinding
from .rules import RuleEngine


C_CPP_CALL_REGEX = re.compile(
    r'\b(?P<call>EVP_aes_\d{3}_[a-z0-9]+|EVP_des_[a-z0-9_]+|RSA_generate_key_ex|'
    r'EVP_sha\d+|EVP_md5|crypto_box_keypair|crypto_sign_keypair|crypto_secretbox_easy)\b'
)


class CPPScanner(BaseSourceScanner):
    """Scanner for C and C++ source files."""

    def supported_extensions(self) -> List[str]:
        return [".c", ".cpp", ".cc", ".cxx", ".h", ".hpp"]

    def parse_file(self, file_path: Path) -> List[SourceFinding]:
        findings: List[SourceFinding] = []
        try:
            with open(file_path, "r", encoding="utf-8", errors="replace") as f:
                lines = f.readlines()
        except Exception:
            return []

        for line_idx, line in enumerate(lines, start=1):
            for match in C_CPP_CALL_REGEX.finditer(line):
                call_name = match.group("call")
                col = match.start()

                algo_rule = None
                mode = None
                call_lower = call_name.lower()

                if "aes" in call_lower:
                    algo_rule = self.rule_engine.algorithms.get("ALGO-AES")
                    if "ecb" in call_lower:
                        mode = "ECB"
                    elif "cbc" in call_lower:
                        mode = "CBC"
                    elif "gcm" in call_lower:
                        mode = "GCM"
                elif "des_ede3" in call_lower:
                    algo_rule = self.rule_engine.algorithms.get("ALGO-3DES")
                elif "des" in call_lower:
                    algo_rule = self.rule_engine.algorithms.get("ALGO-DES")
                elif "rsa" in call_lower:
                    algo_rule = self.rule_engine.algorithms.get("ALGO-RSA")
                elif "md5" in call_lower:
                    algo_rule = self.rule_engine.algorithms.get("ALGO-MD5")
                elif "sha256" in call_lower:
                    algo_rule = self.rule_engine.algorithms.get("ALGO-SHA2-256")
                elif "sha" in call_lower:
                    algo_rule = self.rule_engine.algorithms.get("ALGO-SHA2")
                elif "crypto_box" in call_lower:
                    algo_rule = self.rule_engine.algorithms.get("ALGO-X25519")
                elif "crypto_sign" in call_lower:
                    algo_rule = self.rule_engine.algorithms.get("ALGO-ED25519")
                elif "crypto_secretbox" in call_lower:
                    algo_rule = self.rule_engine.algorithms.get("ALGO-XSALSA20-POLY1305")

                sec_findings = []
                if mode == "ECB":
                    sec_findings.append({
                        "issue": "Insecure ECB cipher mode invoked via OpenSSL/BoringSSL",
                        "severity": "CRITICAL"
                    })
                if algo_rule and algo_rule.id in ["ALGO-DES", "ALGO-3DES", "ALGO-MD5"]:
                    sec_findings.append({
                        "issue": f"Legacy/broken cryptographic primitive used: {algo_rule.name}",
                        "severity": "HIGH"
                    })

                snippet = self.extract_snippet(file_path, line_idx)
                findings.append(SourceFinding(
                    source_domain="source_code",
                    language="cpp",
                    file_path=str(file_path.resolve()),
                    line_number=line_idx,
                    column_number=col,
                    code_snippet=snippet,
                    primitive=algo_rule.primitive if algo_rule else "cryptographic_operation",
                    algorithm=algo_rule.name if algo_rule else call_name,
                    mode=mode,
                    quantum_safe=algo_rule.quantum_safe if algo_rule else False,
                    nist_status=algo_rule.nist_status if algo_rule else "unknown",
                    security_findings=sec_findings,
                    raw_metadata={"c_api_call": call_name}
                ))

        return findings