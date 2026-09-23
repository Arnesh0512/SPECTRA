"""
spectra.scanners.artifacts.binary_scanner
==============================================
Executable binary and shared object cryptographic scanner.
Discovers linked cryptographic shared libraries, symbol table entries,
and binary string constants across ELF, PE, and Mach-O files.
"""

from dataclasses import dataclass, field
from pathlib import Path
import re
from typing import Any, Dict, List, Optional, Set

from spectra.utils.shell import command_exists, extract_printable_strings, run_command


@dataclass
class BinaryFinding:
    """Represents cryptographic evidence found within a binary file."""
    source_domain: str = "artifacts"
    artifact_type: str = "compiled_binary"
    file_path: str = ""
    binary_format: str = "unknown"  # ELF, PE, Mach-O, unknown
    linked_crypto_libraries: List[str] = field(default_factory=list)
    detected_symbols: List[str] = field(default_factory=list)
    detected_algorithms: List[str] = field(default_factory=list)
    quantum_safe: bool = False
    security_findings: List[Dict[str, str]] = field(default_factory=list)
    raw_metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "source_domain": self.source_domain,
            "artifact_type": self.artifact_type,
            "file_path": self.file_path,
            "binary_format": self.binary_format,
            "linked_crypto_libraries": self.linked_crypto_libraries,
            "detected_symbols": self.detected_symbols,
            "detected_algorithms": self.detected_algorithms,
            "quantum_safe": self.quantum_safe,
            "security_findings": self.security_findings,
            "raw_metadata": self.raw_metadata
        }


# Known cryptographic dynamic libraries
CRYPTO_SHARED_LIBS = {
    "libcrypto.so", "libssl.so", "libsodium.so", "libnettle.so",
    "libmbedcrypto.so", "libwolfssl.so", "bcrypt.dll", "crypt32.dll",
    "ncrypt.dll", "libcrypto.dylib", "libssl.dylib"
}

# Regex to detect symbol names associated with crypto primitives
CRYPTO_SYMBOL_REGEX = re.compile(
    r"\b(EVP_aes_\w+|EVP_des_\w+|EVP_sha\w+|EVP_md5|RSA_generate_\w+|"
    r"crypto_box_\w+|crypto_sign_\w+|BCryptEncrypt|BCryptGenRandom|"
    r"mbedtls_aes_\w+|wolfSSL_AES_\w+)\b",
    re.IGNORECASE
)

# Regex to catch explicit algorithm names in string pools
ALGO_STRING_REGEX = re.compile(
    r"\b(AES-(?:128|192|256)-(?:GCM|CBC|CTR|ECB)|DES-EDE3-CBC|MD5|SHA256|SHA512|ML-KEM|Kyber-768)\b",
    re.IGNORECASE
)


class BinaryScanner:
    """Discovers and inspects compiled binaries for cryptographic linkages."""

    BINARY_EXTENSIONS = {".so", ".dll", ".dylib", ".exe", ".bin", ""}

    def scan_directory(self, target_dir: Path, excluded_dirs: Optional[List[str]] = None) -> List[BinaryFinding]:
        findings: List[BinaryFinding] = []
        excluded = set(excluded_dirs or [])

        for path in target_dir.rglob("*"):
            if not path.is_file():
                continue
            if any(part in excluded for part in path.parts):
                continue

            # Check matching extension or executable permission bit
            if path.suffix.lower() in self.BINARY_EXTENSIONS:
                if self._is_binary_file(path):
                    finding = self.scan_binary(path)
                    if finding:
                        findings.append(finding)

        return findings

    def scan_binary(self, file_path: Path) -> Optional[BinaryFinding]:
        binary_fmt = self._detect_format(file_path)
        if binary_fmt == "non_binary":
            return None

        linked_libs: Set[str] = set()
        detected_symbols: Set[str] = set()
        detected_algos: Set[str] = set()

        # 1. Inspect dynamic shared libraries (ldd/readelf/strings)
        if binary_fmt == "ELF" and command_exists("readelf"):
            code, stdout, _ = run_command(["readelf", "-d", str(file_path)])
            if code == 0:
                for line in stdout.splitlines():
                    if "NEEDED" in line:
                        for clib in CRYPTO_SHARED_LIBS:
                            if clib in line.lower():
                                linked_libs.add(clib)

        # 2. Inspect symbol tables (nm/readelf/strings)
        if binary_fmt == "ELF" and command_exists("readelf"):
            code, stdout, _ = run_command(["readelf", "-s", "--wide", str(file_path)])
            if code == 0:
                for match in CRYPTO_SYMBOL_REGEX.finditer(stdout):
                    detected_symbols.add(match.group(0))

        # 3. String pool extraction fallback & algorithm signature search
        strings = extract_printable_strings(file_path, min_length=4, limit=30000)
        for s in strings:
            for clib in CRYPTO_SHARED_LIBS:
                if clib in s.lower():
                    linked_libs.add(clib)
            for sm in CRYPTO_SYMBOL_REGEX.finditer(s):
                detected_symbols.add(sm.group(0))
            for am in ALGO_STRING_REGEX.finditer(s):
                detected_algos.add(am.group(0))

        # Only create a finding if cryptographic footprint is present
        if not (linked_libs or detected_symbols or detected_algos):
            return None

        sec_findings = []
        for sym in detected_symbols:
            if "md5" in sym.lower() or "des" in sym.lower():
                sec_findings.append({
                    "issue": f"Legacy/broken cryptographic symbol referenced in binary: {sym}",
                    "severity": "HIGH"
                })
        for algo in detected_algos:
            if "ECB" in algo.upper():
                sec_findings.append({
                    "issue": f"Insecure ECB cipher mode reference detected in binary string pool: {algo}",
                    "severity": "HIGH"
                })

        return BinaryFinding(
            source_domain="artifacts",
            artifact_type="compiled_binary",
            file_path=str(file_path.resolve()),
            binary_format=binary_fmt,
            linked_crypto_libraries=sorted(list(linked_libs)),
            detected_symbols=sorted(list(detected_symbols)),
            detected_algorithms=sorted(list(detected_algos)),
            quantum_safe=any("ML-KEM" in a or "Kyber" in a for a in detected_algos),
            security_findings=sec_findings,
            raw_metadata={"strings_analyzed_count": len(strings)}
        )

    def _detect_format(self, file_path: Path) -> str:
        """Determines binary header type using magic byte inspection."""
        try:
            with open(file_path, "rb") as f:
                header = f.read(4)
            if header.startswith(b"\x7fELF"):
                return "ELF"
            elif header.startswith(b"MZ"):
                return "PE"
            elif header in (b"\xfe\xed\xfa\xce", b"\xfe\xed\xfa\xcf", b"\xce\xfa\xed\xfe", b"\xcf\xfa\xed\xfe"):
                return "Mach-O"
            return "unknown"
        except Exception:
            return "non_binary"

    def _is_binary_file(self, file_path: Path) -> bool:
        """Checks if file contains null bytes within the first 1024 bytes."""
        try:
            with open(file_path, "rb") as f:
                chunk = f.read(1024)
            return b"\x00" in chunk
        except Exception:
            return False