"""
spectra.scanners.source.compiled_src
=========================================
Source code cryptographic scanner for compiled languages:
C/C++ (OpenSSL, BoringSSL, libsodium), Go (crypto/*), and Rust (ring, aes_gcm, rsa).
"""

from pathlib import Path
import re
from typing import List, Optional

from .base import BaseSourceScanner, SourceFinding
from .rules import RuleEngine


# C/C++ patterns (OpenSSL / libsodium / BoringSSL)
C_CPP_CALL_REGEX = re.compile(
    r'\b(?P<call>EVP_aes_\d{3}_[a-z0-9]+|EVP_des_[a-z0-9_]+|RSA_generate_key_ex|'
    r'EVP_sha\d+|EVP_md5|crypto_box_keypair|crypto_sign_keypair|crypto_secretbox_easy)\b'
)

# Go patterns (crypto/aes, crypto/rsa, crypto/ecdsa, etc.)
GO_CALL_REGEX = re.compile(
    r'\b(?P<pkg>aes|des|rsa|ecdsa|sha256|sha512|md5)\.(?P<method>NewCipher|NewTripleDESCipher|GenerateKey|New)\b'
)

# Rust patterns (ring, aes_gcm, rsa)
RUST_CALL_REGEX = re.compile(
    r'\b(?P<class>Aes128Gcm|Aes256Gcm|RsaPrivateKey|aead::AES_256_GCM|aead::CHACHA20_POLY1305)::(?P<method>new|generate|new_with_rng)\b'
)


class CompiledLanguageScanner(BaseSourceScanner):
    """Scanner for C/C++, Go, and Rust source files."""

    def supported_extensions(self) -> List[str]:
        return [".c", ".cpp", ".cc", ".cxx", ".h", ".hpp", ".go", ".rs"]

    def parse_file(self, file_path: Path) -> List[SourceFinding]:
        findings: List[SourceFinding] = []
        ext = file_path.suffix.lower()

        try:
            with open(file_path, "r", encoding="utf-8", errors="replace") as f:
                lines = f.readlines()
        except Exception:
            return []

        for line_idx, line in enumerate(lines, start=1):
            if ext in [".c", ".cpp", ".cc", ".cxx", ".h", ".hpp"]:
                self._scan_c_cpp_line(file_path, line_idx, line, findings)
            elif ext == ".go":
                self._scan_go_line(file_path, line_idx, line, findings)
            elif ext == ".rs":
                self._scan_rust_line(file_path, line_idx, line, findings)

        return findings

    def _scan_c_cpp_line(self, file_path: Path, line_idx: int, line: str, out_list: List[SourceFinding]):
        for match in C_CPP_CALL_REGEX.finditer(line):
            call_name = match.group("call")
            col = match.start()

            algo_rule = None
            mode = None
            if "aes" in call_name.lower():
                algo_rule = self.rule_engine.algorithms.get("ALGO-AES")
                if "ecb" in call_name.lower():
                    mode = "ECB"
                elif "cbc" in call_name.lower():
                    mode = "CBC"
                elif "gcm" in call_name.lower():
                    mode = "GCM"
            elif "des" in call_name.lower():
                algo_rule = self.rule_engine.algorithms.get("ALGO-DES")
            elif "rsa" in call_name.lower():
                algo_rule = self.rule_engine.algorithms.get("ALGO-RSA")
            elif "md5" in call_name.lower():
                algo_rule = self.rule_engine.algorithms.get("ALGO-MD5")
            elif "sha" in call_name.lower():
                algo_rule = self.rule_engine.algorithms.get("ALGO-SHA2")

            sec_findings = []
            if mode == "ECB":
                sec_findings.append({
                    "issue": "Insecure ECB cipher mode invoked via OpenSSL/BoringSSL",
                    "severity": "CRITICAL"
                })
            if algo_rule and algo_rule.id in ["ALGO-DES", "ALGO-MD5"]:
                sec_findings.append({
                    "issue": f"Legacy/broken cryptographic primitive used: {algo_rule.name}",
                    "severity": "HIGH"
                })

            snippet = self.extract_snippet(file_path, line_idx)
            out_list.append(SourceFinding(
                source_domain="source_code",
                language="c_cpp",
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

    def _scan_go_line(self, file_path: Path, line_idx: int, line: str, out_list: List[SourceFinding]):
        for match in GO_CALL_REGEX.finditer(line):
            pkg = match.group("pkg").lower()
            method = match.group("method")
            col = match.start()

            algo_map = {
                "aes": "ALGO-AES",
                "des": "ALGO-DES",
                "rsa": "ALGO-RSA",
                "ecdsa": "ALGO-ECDSA",
                "sha256": "ALGO-SHA2",
                "sha512": "ALGO-SHA2",
                "md5": "ALGO-MD5"
            }
            algo_id = algo_map.get(pkg)
            algo_rule = self.rule_engine.algorithms.get(algo_id) if algo_id else None

            sec_findings = []
            if pkg in ["des", "md5"]:
                sec_findings.append({
                    "issue": f"Deprecated Go crypto package invoked: crypto/{pkg}",
                    "severity": "HIGH"
                })

            snippet = self.extract_snippet(file_path, line_idx)
            out_list.append(SourceFinding(
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

    def _scan_rust_line(self, file_path: Path, line_idx: int, line: str, out_list: List[SourceFinding]):
        for match in RUST_CALL_REGEX.finditer(line):
            cls = match.group("class")
            method = match.group("method")
            col = match.start()

            algo_rule = None
            if "aes" in cls.lower():
                algo_rule = self.rule_engine.algorithms.get("ALGO-AES")
            elif "rsa" in cls.lower():
                algo_rule = self.rule_engine.algorithms.get("ALGO-RSA")
            elif "chacha" in cls.lower():
                algo_rule = self.rule_engine.algorithms.get("ALGO-CHACHA20")

            snippet = self.extract_snippet(file_path, line_idx)
            out_list.append(SourceFinding(
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