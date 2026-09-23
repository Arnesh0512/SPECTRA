"""
spectra.scanners.source.jvm_scanner
========================================
Java and Kotlin source code cryptographic scanner.
Analyzes JCA/JCE APIs, KeyPairGenerators, MessageDigest calls, and Bouncy Castle
operations by parsing transformation strings (e.g., 'AES/GCM/NoPadding').
"""

from pathlib import Path
import re
from typing import List, Optional, Tuple

from .base import BaseSourceScanner, SourceFinding
from .rules import RuleEngine


# Regular expressions to locate JCA/JCE API calls
JCA_CALL_REGEX = re.compile(
    r'(?P<class>Cipher|KeyGenerator|KeyPairGenerator|MessageDigest|Signature|Mac)'
    r'\s*\.\s*getInstance\s*\(\s*["\'](?P<spec>[^"\']+)["\']',
    re.IGNORECASE
)

# Regex to detect Bouncy Castle PQC generator instantiations
BC_PQC_REGEX = re.compile(
    r'new\s+(?P<class>(Kyber|Dilithium|SPHINCSPlus|Falcon|BIKE|HQC)KeyPairGenerator)\s*\(',
    re.IGNORECASE
)


class JVMScanner(BaseSourceScanner):
    """Scanner for Java (.java) and Kotlin (.kt) source files."""

    def supported_extensions(self) -> List[str]:
        return [".java", ".kt"]

    def parse_file(self, file_path: Path) -> List[SourceFinding]:
        findings: List[SourceFinding] = []
        try:
            with open(file_path, "r", encoding="utf-8", errors="replace") as f:
                lines = f.readlines()
        except Exception:
            return []

        for line_idx, line in enumerate(lines, start=1):
            # 1. Check standard JCA/JCE getInstance(...) invocations
            for match in JCA_CALL_REGEX.finditer(line):
                class_name = match.group("class")
                spec_str = match.group("spec").strip()
                col_offset = match.start()

                finding = self._process_jca_finding(
                    file_path=file_path,
                    line_idx=line_idx,
                    col_offset=col_offset,
                    class_name=class_name,
                    spec=spec_str
                )
                if finding:
                    findings.append(finding)

            # 2. Check direct Bouncy Castle PQC instantiations
            for match in BC_PQC_REGEX.finditer(line):
                class_name = match.group("class")
                col_offset = match.start()
                finding = self._process_bc_pqc_finding(
                    file_path=file_path,
                    line_idx=line_idx,
                    col_offset=col_offset,
                    class_name=class_name
                )
                if finding:
                    findings.append(finding)

        return findings

    def _process_jca_finding(
        self,
        file_path: Path,
        line_idx: int,
        col_offset: int,
        class_name: str,
        spec: str
    ) -> Optional[SourceFinding]:
        algo_name, mode, padding = self._parse_transformation(spec)
        algo_rule = self.rule_engine.match_algorithm_by_name_or_pattern(algo_name)

        primitive = algo_rule.primitive if algo_rule else self._map_class_to_primitive(class_name)
        quantum_safe = algo_rule.quantum_safe if algo_rule else False
        nist_status = algo_rule.nist_status if algo_rule else "unknown"

        sec_findings = []
        # Flag weak/insecure cipher modes (e.g. ECB)
        if mode and mode.upper() in ["ECB", "NONE"]:
            sec_findings.append({
                "issue": f"Insecure block cipher mode '{mode}' detected in transformation '{spec}'",
                "severity": "CRITICAL"
            })

        # Flag deprecated classical algorithms
        if algo_name.upper() in ["DES", "3DES", "DESEDE", "MD5", "SHA1", "SHA-1"]:
            sec_findings.append({
                "issue": f"Legacy/broken cryptographic algorithm '{algo_name}' invoked via JCA",
                "severity": "HIGH"
            })

        code_snippet = self.extract_snippet(file_path, line_idx)

        return SourceFinding(
            source_domain="source_code",
            language="jvm",
            file_path=str(file_path.resolve()),
            line_number=line_idx,
            column_number=col_offset,
            code_snippet=code_snippet,
            primitive=primitive,
            algorithm=algo_rule.name if algo_rule else algo_name,
            mode=mode,
            padding=padding,
            quantum_safe=quantum_safe,
            nist_status=nist_status,
            security_findings=sec_findings,
            raw_metadata={"jca_class": class_name, "raw_spec": spec}
        )

    def _process_bc_pqc_finding(
        self,
        file_path: Path,
        line_idx: int,
        col_offset: int,
        class_name: str
    ) -> SourceFinding:
        name_clean = class_name.replace("KeyPairGenerator", "")
        algo_rule = self.rule_engine.match_algorithm_by_name_or_pattern(name_clean)

        code_snippet = self.extract_snippet(file_path, line_idx)
        return SourceFinding(
            source_domain="source_code",
            language="jvm",
            file_path=str(file_path.resolve()),
            line_number=line_idx,
            column_number=col_offset,
            code_snippet=code_snippet,
            primitive=algo_rule.primitive if algo_rule else "key_encapsulation",
            algorithm=algo_rule.name if algo_rule else name_clean,
            quantum_safe=True,
            nist_status=algo_rule.nist_status if algo_rule else "approved_pqc",
            security_findings=[],
            raw_metadata={"bouncy_castle_class": class_name}
        )

    def _parse_transformation(self, spec: str) -> Tuple[str, Optional[str], Optional[str]]:
        """
        Parses standard JCA transformation strings:
        e.g., 'AES/CBC/PKCS5Padding' -> ('AES', 'CBC', 'PKCS5Padding')
              'RSA/ECB/OAEPWithSHA-256AndMGF1Padding' -> ('RSA', 'ECB', 'OAEP...')
              'SHA-256' -> ('SHA-256', None, None)
        """
        parts = spec.split("/")
        if len(parts) == 3:
            return parts[0], parts[1], parts[2]
        elif len(parts) == 2:
            return parts[0], parts[1], None
        return spec, None, None

    def _map_class_to_primitive(self, class_name: str) -> str:
        mapping = {
            "Cipher": "symmetric_cipher",
            "KeyGenerator": "symmetric_key_gen",
            "KeyPairGenerator": "public_key",
            "MessageDigest": "hash",
            "Signature": "signature",
            "Mac": "mac"
        }
        return mapping.get(class_name, "cryptographic_operation")