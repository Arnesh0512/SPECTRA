"""
spectra.scanners.source.js_ts_scanner
==========================================
JavaScript and TypeScript source code cryptographic scanner.
Inspects Node.js 'crypto' module invocations, browser WebCrypto subtle APIs,
and third-party libraries (crypto-js, node-forge) via pattern and token matching.
"""

from pathlib import Path
import re
from typing import List, Optional

from .base import BaseSourceScanner, SourceFinding
from .rules import RuleEngine


# Regex patterns matching common JS/TS crypto calls and arguments
NODE_CIPHER_REGEX = re.compile(
    r'(?:crypto\.)?create(?:Cipher|Decipher)iv\s*\(\s*["\'](?P<algo>[^"\']+)["\']',
    re.IGNORECASE
)

NODE_HASH_REGEX = re.compile(
    r'(?:crypto\.)?create(?:Hash|Hmac)\s*\(\s*["\'](?P<algo>[^"\']+)["\']',
    re.IGNORECASE
)

NODE_KEYPAIR_REGEX = re.compile(
    r'(?:crypto\.)?generateKeyPair(?:Sync)?\s*\(\s*["\'](?P<type>[^"\']+)["\']',
    re.IGNORECASE
)

CRYPTO_JS_CALL_REGEX = re.compile(
    r'CryptoJS\.(?P<algo>AES|DES|TripleDES|RC4|Rabbit|MD5|SHA1|SHA256|SHA512|HmacSHA256)\.(?:encrypt|decrypt)?',
    re.IGNORECASE
)

WEBCRYPTO_SUBTLE_REGEX = re.compile(
    r'crypto\.subtle\.(?:generateKey|encrypt|decrypt|sign|digest)\s*\(\s*(?:\{[^}]*name\s*:\s*["\'](?P<algo>[^"\']+)["\']|["\'](?P<algo_direct>[^"\']+)["\'])',
    re.IGNORECASE
)


class JSTSSParser(BaseSourceScanner):
    """Scanner for JavaScript (.js, .jsx, .mjs) and TypeScript (.ts, .tsx) files."""

    def supported_extensions(self) -> List[str]:
        return [".js", ".jsx", ".mjs", ".ts", ".tsx"]

    def parse_file(self, file_path: Path) -> List[SourceFinding]:
        findings: List[SourceFinding] = []
        try:
            with open(file_path, "r", encoding="utf-8", errors="replace") as f:
                lines = f.readlines()
        except Exception:
            return []

        for line_idx, line in enumerate(lines, start=1):
            # 1. Check Node.js createCipheriv / createDecipheriv
            for match in NODE_CIPHER_REGEX.finditer(line):
                algo_str = match.group("algo")
                col = match.start()
                finding = self._build_finding(
                    file_path=file_path,
                    line_idx=line_idx,
                    col=col,
                    raw_name=algo_str,
                    call_type="node_crypto_cipher",
                    primitive="symmetric_cipher"
                )
                if finding:
                    findings.append(finding)

            # 2. Check Node.js createHash / createHmac
            for match in NODE_HASH_REGEX.finditer(line):
                algo_str = match.group("algo")
                col = match.start()
                finding = self._build_finding(
                    file_path=file_path,
                    line_idx=line_idx,
                    col=col,
                    raw_name=algo_str,
                    call_type="node_crypto_hash",
                    primitive="hash"
                )
                if finding:
                    findings.append(finding)

            # 3. Check Node.js generateKeyPair / generateKeyPairSync
            for match in NODE_KEYPAIR_REGEX.finditer(line):
                algo_str = match.group("type")
                col = match.start()
                finding = self._build_finding(
                    file_path=file_path,
                    line_idx=line_idx,
                    col=col,
                    raw_name=algo_str,
                    call_type="node_crypto_keypair",
                    primitive="public_key"
                )
                if finding:
                    findings.append(finding)

            # 4. Check CryptoJS calls
            for match in CRYPTO_JS_CALL_REGEX.finditer(line):
                algo_str = match.group("algo")
                col = match.start()
                finding = self._build_finding(
                    file_path=file_path,
                    line_idx=line_idx,
                    col=col,
                    raw_name=algo_str,
                    call_type="crypto_js",
                    primitive="symmetric_cipher" if "DES" in algo_str.upper() or "AES" in algo_str.upper() else "hash"
                )
                if finding:
                    findings.append(finding)

            # 5. Check WebCrypto subtle calls
            for match in WEBCRYPTO_SUBTLE_REGEX.finditer(line):
                algo_str = match.group("algo") or match.group("algo_direct") or "unknown"
                col = match.start()
                finding = self._build_finding(
                    file_path=file_path,
                    line_idx=line_idx,
                    col=col,
                    raw_name=algo_str,
                    call_type="webcrypto_subtle",
                    primitive="cryptographic_operation"
                )
                if finding:
                    findings.append(finding)

        return findings

    def _build_finding(
        self,
        file_path: Path,
        line_idx: int,
        col: int,
        raw_name: str,
        call_type: str,
        primitive: str
    ) -> Optional[SourceFinding]:
        algo_rule = self.rule_engine.match_algorithm_by_name_or_pattern(raw_name)

        algo_name = algo_rule.name if algo_rule else raw_name
        resolved_primitive = algo_rule.primitive if algo_rule else primitive
        quantum_safe = algo_rule.quantum_safe if algo_rule else False
        nist_status = algo_rule.nist_status if algo_rule else "unknown"

        mode = None
        # Extract mode for ciphers like aes-256-cbc or aes-128-ecb
        parts = raw_name.lower().split("-")
        if len(parts) >= 3 and parts[-1] in ["cbc", "gcm", "ecb", "ctr", "cfb", "ofb"]:
            mode = parts[-1].upper()

        sec_findings = []
        if mode == "ECB":
            sec_findings.append({
                "issue": f"Insecure block cipher mode 'ECB' detected in cipher string '{raw_name}'",
                "severity": "CRITICAL"
            })

        if raw_name.lower() in ["md5", "sha1", "des", "3des", "rc4"]:
            sec_findings.append({
                "issue": f"Broken or deprecated algorithm '{raw_name}' invoked in JavaScript/TypeScript",
                "severity": "HIGH"
            })

        snippet = self.extract_snippet(file_path, line_idx)

        return SourceFinding(
            source_domain="source_code",
            language="js_ts",
            file_path=str(file_path.resolve()),
            line_number=line_idx,
            column_number=col,
            code_snippet=snippet,
            primitive=resolved_primitive,
            algorithm=algo_name,
            mode=mode,
            quantum_safe=quantum_safe,
            nist_status=nist_status,
            security_findings=sec_findings,
            raw_metadata={"js_call_type": call_type, "raw_token": raw_name}
        )