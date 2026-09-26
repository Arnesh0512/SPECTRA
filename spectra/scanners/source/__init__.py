"""
spectra.scanners.source
============================
Unified source code scanner coordinating dynamic rule-driven pre-filtering (ripgrep)
and language-specific AST and pattern parsers.
"""

from pathlib import Path
import re
from typing import Dict, List, Set, Optional

from spectra.config import ScanConfig
from spectra.utils.logger import log_info, log_step, log_warning
from spectra.utils.shell import command_exists, run_command

from .base import BaseSourceScanner, SourceFinding
from .python_scanner import PythonASTScanner
from .jvm_scanner import JVMScanner
from .js_ts_scanner import JSTSSParser
from .cpp_scanner import CPPScanner
from .go_scanner import GoScanner
from .rust_scanner import RustScanner
from .rules import DEFAULT_RULE_ENGINE, RuleEngine


class SourceScanOrchestrator:
    """Manages discovery and AST dispatch across all supported source code files."""

    def __init__(self, config: ScanConfig, rule_engine: RuleEngine = DEFAULT_RULE_ENGINE):
        self.config = config
        self.rule_engine = rule_engine
        self.scanners: List[BaseSourceScanner] = [
            PythonASTScanner(rule_engine=self.rule_engine),
            JVMScanner(rule_engine=self.rule_engine),
            JSTSSParser(rule_engine=self.rule_engine),
            CPPScanner(rule_engine=self.rule_engine),
            GoScanner(rule_engine=self.rule_engine),
            RustScanner(rule_engine=self.rule_engine),
        ]
        self.ext_to_scanner: Dict[str, BaseSourceScanner] = {}
        for scanner in self.scanners:
            for ext in scanner.supported_extensions():
                self.ext_to_scanner[ext] = scanner

        # Build dynamic, high-recall regex pattern from loaded YAML knowledge base
        self.dynamic_crypto_regex = self._build_dynamic_regex()

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

    def _build_dynamic_regex(self) -> str:
        """
        Dynamically derives regex search tokens from all registered YAML rules
        combining library imports, C/C++ headers, and core crypto classes.
        """
        raw_tokens: Set[str] = set()

        # 1. Pull imports and headers from loaded YAML libraries
        for lang, lib_rules in self.rule_engine.libraries_by_language.items():
            for lib in lib_rules:
                for imp in lib.imports:
                    raw_tokens.add(imp.split(".")[0])
                    raw_tokens.add(imp.replace(".", r"[/\\.]"))
                for hdr in lib.headers:
                    raw_tokens.add(hdr.replace("/", r"[/\\.]"))

                for cp in lib.call_patterns:
                    if cp.class_name:
                        raw_tokens.add(cp.class_name)
                    if cp.call and "." in cp.call:
                        raw_tokens.add(cp.call.split(".")[0])

        # 2. Add high-confidence fallback anchors
        fallback_anchors = {
            "cryptography", "Crypto", "Cryptodome", "hashlib", "nacl",
            "javax.crypto", "java.security", "bouncycastle", "ECGenParameterSpec",
            "KeyStore", "KeyPairGenerator", "Cipher", "MessageDigest",
            "crypto-js", "subtle", "createCipheriv", "createHash",
            "crypto/aes", "crypto/rsa", "crypto/tls", "crypto/ecdsa",
            "ring::", "aes_gcm", "rustls", "openssl", "sodium"
        }
        raw_tokens.update(fallback_anchors)

        sorted_tokens = sorted([re.escape(t).replace(r"\[/\\\.\]", r"[/\\.]") for t in raw_tokens if len(t) >= 3], key=len, reverse=True)
        return r"\b(" + "|".join(sorted_tokens) + r")"

    def _run_ripgrep_filter(self, target_dir: Path) -> Set[Path]:
        """Executes optimized ripgrep subprocess with exclusion and multiline matching."""
        candidates: Set[Path] = set()
        
        ext_globs = []
        for ext in self.ext_to_scanner.keys():
            ext_globs.extend(["-g", f"*{ext}"])

        exclude_globs = []
        for ex in self.config.source_scanner.excluded_directories:
            exclude_globs.extend(["-g", f"!**/{ex}/**"])

        cmd = [
            "rg",
            "-l",
            "--no-messages",
            "--color", "never",
            "--mmap",
            "--max-filesize", "5M",
            "-e", self.dynamic_crypto_regex,
            *ext_globs,
            *exclude_globs,
            str(target_dir)
        ]

        exit_code, stdout, stderr = run_command(cmd)

        if exit_code in (0, 1):
            for line in stdout.splitlines():
                clean_path = line.strip()
                if clean_path:
                    candidates.add(Path(clean_path).resolve())
            return candidates

        log_warning(f"ripgrep returned code {exit_code} ({stderr.strip()}), falling back to Python file walker.")
        return self._run_python_fallback_filter(target_dir)

    def _run_python_fallback_filter(self, target_dir: Path) -> Set[Path]:
        """High-throughput pure-Python fallback candidate search."""
        candidates: Set[Path] = set()
        compiled_regex = re.compile(self.dynamic_crypto_regex, re.IGNORECASE)
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