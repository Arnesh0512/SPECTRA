"""
spectra.scanners.source.python_scanner
===========================================
Python AST-based cryptographic scanner.
Inspects Python syntax trees to detect cryptographic operations, cipher modes,
key sizes, and insecure configurations without executing target code.
"""

import ast
from pathlib import Path
from typing import Dict, List, Optional, Any

from .base import BaseSourceScanner, SourceFinding
from .rules import RuleEngine


class CryptoASTVisitor(ast.NodeVisitor):
    """Walks the Python AST to locate and extract cryptographic operations."""

    def __init__(self, file_path: Path, rule_engine: RuleEngine, scanner_ref: BaseSourceScanner):
        self.file_path = file_path
        self.rule_engine = rule_engine
        self.scanner_ref = scanner_ref
        self.findings: List[SourceFinding] = []
        # Maps local aliases to fully qualified imports, e.g. {"AES": "Crypto.Cipher.AES"}
        self.imported_names: Dict[str, str] = {}

    def visit_Import(self, node: ast.Import):
        for alias in node.names:
            name = alias.name
            asname = alias.asname or name
            self.imported_names[asname] = name
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom):
        mod = node.module or ""
        for alias in node.names:
            full_name = f"{mod}.{alias.name}" if mod else alias.name
            asname = alias.asname or alias.name
            self.imported_names[asname] = full_name
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call):
        call_name = self._resolve_call_name(node.func)
        if call_name:
            self._analyze_call(call_name, node)
        self.generic_visit(node)

    def _resolve_call_name(self, func_node: ast.AST) -> str:
        """Resolves an AST node representing a function call into a string representation."""
        if isinstance(func_node, ast.Name):
            # e.g., sha256() or Cipher()
            return self.imported_names.get(func_node.id, func_node.id)
        elif isinstance(func_node, ast.Attribute):
            # e.g., AES.new(...) or hashlib.md5(...)
            value_part = self._resolve_call_name(func_node.value)
            return f"{value_part}.{func_node.attr}" if value_part else func_node.attr
        return ""

    def _analyze_call(self, call_name: str, node: ast.Call):
        """Matches resolved function calls against known cryptographic signatures."""
        python_rules = self.rule_engine.get_library_rules_for_language("python")

        for lib in python_rules:
            for pattern in lib.call_patterns:
                if pattern.call and (call_name == pattern.call or call_name.endswith(f".{pattern.call}")):
                    self._record_call_finding(pattern, node, call_name)
                    return

    def _record_call_finding(self, pattern: Any, node: ast.Call, full_call_name: str):
        algo_id = pattern.algo_id or pattern.default_algo_id
        algo_rule = self.rule_engine.algorithms.get(algo_id) if algo_id else None

        algo_name = algo_rule.name if algo_rule else "Unknown"
        primitive = algo_rule.primitive if algo_rule else "cryptographic_operation"
        quantum_safe = algo_rule.quantum_safe if algo_rule else False
        nist_status = algo_rule.nist_status if algo_rule else "unknown"

        mode_val = self._extract_cipher_mode(node)
        key_size = self._extract_key_size(node)

        sec_findings = []
        if pattern.flag_insecure:
            sec_findings.append({
                "issue": f"Deprecated or insecure cryptographic algorithm used ({algo_name})",
                "severity": "HIGH"
            })

        if mode_val and any(insec_m in mode_val for insec_m in pattern.flag_insecure_modes):
            sec_findings.append({
                "issue": f"Insecure cipher mode detected ({mode_val}) - vulnerable to pattern leakage",
                "severity": "CRITICAL"
            })

        if key_size and "key_size_less_than" in pattern.flag_insecure_if:
            threshold = pattern.flag_insecure_if["key_size_less_than"]
            if key_size < threshold:
                sec_findings.append({
                    "issue": f"Key size ({key_size} bits) is below the minimum secure threshold ({threshold} bits)",
                    "severity": "HIGH"
                })

        code_snippet = self.scanner_ref.extract_snippet(self.file_path, node.lineno)

        self.findings.append(
            SourceFinding(
                language="python",
                file_path=str(self.file_path.resolve()),
                line_number=node.lineno,
                column_number=node.col_offset,
                code_snippet=code_snippet,
                primitive=primitive,
                algorithm=algo_name,
                key_size=key_size,
                mode=mode_val,
                quantum_safe=quantum_safe,
                nist_status=nist_status,
                security_findings=sec_findings,
                raw_metadata={"call_name": full_call_name}
            )
        )

    def _extract_cipher_mode(self, node: ast.Call) -> Optional[str]:
        """Extracts mode constants like modes.CBC(...) or AES.MODE_ECB."""
        # 1. Search positional arguments
        for arg in node.args:
            mode_str = self._resolve_mode_repr(arg)
            if mode_str:
                return mode_str

        # 2. Search keyword arguments (e.g., mode=...)
        for kw in node.keywords:
            if kw.arg in ("mode", "cipher_mode"):
                return self._resolve_mode_repr(kw.value)
        return None

    def _resolve_mode_repr(self, node: ast.AST) -> Optional[str]:
        if isinstance(node, ast.Attribute):
            return node.attr  # e.g., 'MODE_ECB' or 'CBC'
        elif isinstance(node, ast.Call):
            if isinstance(node.func, ast.Attribute):
                return node.func.attr  # e.g., 'CBC' from modes.CBC(...)
        elif isinstance(node, ast.Constant) and isinstance(node.value, str):
            return node.value
        return None

    def _extract_key_size(self, node: ast.Call) -> Optional[int]:
        """Extracts integer key size arguments (e.g., key_size=2048 or RSA.generate(1024))."""
        # Positional first argument if integer
        if node.args and isinstance(node.args[0], ast.Constant) and isinstance(node.args[0].value, int):
            return node.args[0].value

        # Keyword arguments
        for kw in node.keywords:
            if kw.arg in ("key_size", "bits", "size") and isinstance(kw.value, ast.Constant) and isinstance(kw.value.int if hasattr(kw.value, 'int') else kw.value.value, int):
                return int(kw.value.value)
        return None


class PythonASTScanner(BaseSourceScanner):
    """Concrete scanner for Python source files (.py)."""

    def supported_extensions(self) -> List[str]:
        return [".py"]

    def parse_file(self, file_path: Path) -> List[SourceFinding]:
        try:
            with open(file_path, "r", encoding="utf-8", errors="replace") as f:
                source_code = f.read()

            tree = ast.parse(source_code, filename=str(file_path))
            visitor = CryptoASTVisitor(file_path, self.rule_engine, self)
            visitor.visit(tree)
            return visitor.findings
        except SyntaxError:
            # File has Python syntax errors (e.g. invalid syntax for current runtime); skip gracefully
            return []
        except Exception:
            return []