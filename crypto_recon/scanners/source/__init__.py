"""
crypto_recon.scanners.source
============================
Unified source code scanner coordinating fast pre-filtering (ripgrep)
and language-specific AST and pattern parsers.
"""

from pathlib import Path
import re
from typing import Dict, List, Set

from crypto_recon.config import ScanConfig
from crypto_recon.utils.logger import log_info, log_step, log_warning
from crypto_recon.utils.shell import command_exists, run_command

from .base import BaseSourceScanner, SourceFinding
from .compiled_src import CompiledLanguageScanner
from .js_ts_scanner import JSTSSParser
from .jvm_scanner import JVMScanner
from .python_scanner import PythonASTScanner
from .rules import DEFAULT_RULE_ENGINE, RuleEngine


# Namespace and import regex covering Python, Java/Kotlin, JS/TS, Go, Rust, and C/C++
CRYPTO_IMPORT_REGEX = (
    r"(from\s+(cryptography|Crypto|Cryptodome|hashlib|nacl)|"
    r"import\s+(cryptography|Crypto|hashlib|javax\.crypto|java\.security|org\.bouncycastle)|"
    r"require\s*\(\s*['\"](crypto|crypto-js|node:crypto)['\"]|"
    r"from\s*['\"](crypto|crypto-js)['\"]|"
    r"\"crypto/(aes|rsa|cipher|sha\d+|tls|ecdsa)\"|"
    r"use\s+(ring|aes_gcm|rsa|rustls|sha2)::|"
    r"#include\s*<openssl/(evp|aes|rsa|sha)\.h>|"
    r"#include\s*<sodium\.h>)"
)


class SourceScanOrchestrator:
    """Manages discovery and AST dispatch across all supported source code files."""

    def __init__(self, config: ScanConfig, rule_engine: RuleEngine = DEFAULT_RULE_ENGINE):
        self.config = config
        self.rule_engine = rule_engine
        self.scanners: List[BaseSourceScanner] = [
            PythonASTScanner(rule_engine=self.rule_engine),
            JVMScanner(rule_engine=self.rule_engine),
            JSTSSParser(rule_engine=self.rule_engine),
            CompiledLanguageScanner(rule_engine=self.rule_engine),
        ]
        self.ext_to_scanner: Dict[str, BaseSourceScanner] = {}
        for scanner in self.scanners:
            for ext in scanner.supported_extensions():
                self.ext_to_scanner[ext] = scanner

    def scan(self, target_dir: Path) -> List[SourceFinding]:
        """Executes the two-tier scan pipeline on the target directory."""
        log_step(f"Scanning source code in: {target_dir}")

        # Tier 1: Discover candidate files with crypto signatures
        candidate_files = self._find_candidates(target_dir)
        log_info(f"Identified {len(candidate_files)} candidate crypto source file(s) for deep analysis.")

        # Tier 2: Deep AST / syntax analysis
        all_findings: List[SourceFinding] = []
        for file_path in candidate_files:
            ext = file_path.suffix.lower()
            scanner = self.ext_to_scanner.get(ext)
            if scanner:
                findings = scanner.parse_file(file_path)
                all_findings.extend(findings)

        log_info(f"Source scan completed with {len(all_findings)} finding(s).")
        return all_findings

    def _find_candidates(self, target_dir: Path) -> Set[Path]:
        """Finds candidate files via ripgrep if enabled/available, else uses Python fallback."""
        if self.config.source_scanner.use_ripgrep and command_exists("rg"):
            return self._run_ripgrep_filter(target_dir)
        return self._run_python_fallback_filter(target_dir)

    def _run_ripgrep_filter(self, target_dir: Path) -> Set[Path]:
        """Executes fast ripgrep subprocess to get files matching crypto namespaces."""
        candidates: Set[Path] = set()
        globs = []
        for ext in self.ext_to_scanner.keys():
            globs.extend(["-g", f"*{ext}"])

        cmd = [
            "rg",
            "-l",
            "--no-messages",
            "-e", CRYPTO_IMPORT_REGEX,
            *globs,
            str(target_dir)
        ]

        exit_code, stdout, stderr = run_command(cmd)
        if exit_code == 0:
            for line in stdout.splitlines():
                clean_path = line.strip()
                if clean_path:
                    candidates.add(Path(clean_path).resolve())
            return candidates

        log_warning(f"ripgrep exited with code {exit_code}, falling back to Python file walker.")
        return self._run_python_fallback_filter(target_dir)

    def _run_python_fallback_filter(self, target_dir: Path) -> Set[Path]:
        """Pure-Python candidate file search."""
        candidates: Set[Path] = set()
        compiled_regex = re.compile(CRYPTO_IMPORT_REGEX)
        excluded_dirs = set(self.config.source_scanner.excluded_directories)
        max_lines = self.config.source_scanner.max_header_lines_checked

        for path in target_dir.rglob("*"):
            if not path.is_file():
                continue
            if path.suffix.lower() not in self.ext_to_scanner:
                continue
            if any(part in excluded_dirs for part in path.parts):
                continue

            try:
                with open(path, "r", encoding="utf-8", errors="ignore") as f:
                    header_content = "".join([f.readline() for _ in range(max_lines)])
                    if compiled_regex.search(header_content):
                        candidates.add(path.resolve())
            except Exception:
                continue

        return candidates