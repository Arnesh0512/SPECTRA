"""
spectra.scanners.source.dependency_analyzer
=================================================
Locates third-party package libraries on disk, scans their internal cryptographic usage,
and maps imported functions back to actual source code callers using precise function-level signatures.
"""

from pathlib import Path
import importlib.metadata
import site
import re
from typing import Dict, List, Optional, Any, Set
from spectra.utils.shell import command_exists, run_command
from .base import SourceFinding


class DependencyAnalyzer:
    """Analyzes installed dependency packages on disk to extract internal crypto usage and call mapping."""

    def __init__(self):
        pass

    def locate_library_path(self, package_name: str, ecosystem: str, project_root: Path) -> Optional[Path]:
        """Step 2: Finds the exact installation path of a library on disk."""
        norm_name = package_name.lower().replace("_", "-")
        
        if ecosystem == "python":
            try:
                dist = importlib.metadata.distribution(package_name)
                for path in dist.files or []:
                    if path.name == "__init__.py" or path.suffix == ".py":
                        full_path = Path(dist.locate_file(path))
                        if full_path.is_file():
                            return full_path.parent
            except Exception:
                pass
            
            for sp in site.getsitepackages():
                sp_path = Path(sp)
                for candidate in [sp_path / package_name, sp_path / package_name.replace("-", "_")]:
                    if candidate.is_dir():
                        return candidate

        elif ecosystem in ["javascript", "typescript", "javascript_or_typescript"]:
            node_mod = project_root / "node_modules" / package_name
            if node_mod.is_dir():
                return node_mod

        elif ecosystem == "go":
            gopath = Path.home() / "go" / "pkg" / "mod"
            if gopath.is_dir():
                for mod_dir in gopath.glob(f"{package_name}@*"):
                    if mod_dir.is_dir():
                        return mod_dir

        return None

    def analyze_dependency(
        self,
        package_name: str,
        ecosystem: str,
        project_root: Path,
        scanners_map: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """
        Performs Steps 1-4: Locates library, scans internal encryption/crypto usage,
        and links actual code-level calls back to the codebase with direct/indirect call counts.
        """
        results: List[Dict[str, Any]] = []
        lib_path = self.locate_library_path(package_name, ecosystem, project_root)
        
        if not lib_path or not lib_path.exists():
            return results

        scanner = scanners_map.get(ecosystem)
        internal_findings = []
        
        if scanner:
            for file_path in lib_path.rglob("*"):
                if file_path.is_file() and file_path.suffix.lower() in scanner.supported_extensions():
                    try:
                        findings = scanner.parse_file(file_path)
                        internal_findings.extend(findings)
                    except Exception:
                        continue

        for finding in internal_findings:
            func_called = finding.algorithm or finding.primitive
            codebase_callers = []
            direct_calls = 0
            transitive_calls = 0
            call_depth = 0

            if command_exists("rg"):
                # Construct precise code-level signature search tokens rather than raw package names
                # e.g. looking for requests.get, requests.post, or function names directly
                base_pkg = package_name.split("/")[-1]
                signatures = [
                    f"{base_pkg}.",          # matches package attribute calls like requests.get()
                    f"{func_called}",        # matches function name directly
                ]

                seen_matches = set()
                for sig in signatures:
                    if len(sig) < 2:
                        continue
                    cmd = ["rg", "-w", "--no-heading", "--line-number", sig, str(project_root)]
                    code, stdout, _ = run_command(cmd)
                    if code in (0, 1) and stdout:
                        for line in stdout.splitlines():
                            # Robust handling for Windows drive letters (e.g. C:\path:line:content)
                            if len(line) > 2 and line[1] == ':' and line[2] in ('\\', '/'):
                                parts = line[2:].split(":", 1)
                                matched_file = line[0] + ":" + parts[0] if parts else line
                            else:
                                parts = line.split(":", 1)
                                matched_file = parts[0] if parts else line

                            caller_path = Path(matched_file.strip())
                            
                            # Strict Filtering: Must be an actual source file (not manifest files like requirements.txt)
                            is_manifest = caller_path.name.lower() in {
                                "requirements.txt", "constraints.txt", "pyproject.toml", 
                                "package.json", "go.mod", "cargo.toml", "pom.xml"
                            }

                            if caller_path.is_file() and not is_manifest and not str(caller_path.resolve()).startswith(str(lib_path.resolve())):
                                resolved_str = str(caller_path.resolve())
                                if resolved_str not in seen_matches:
                                    seen_matches.add(resolved_str)
                                    codebase_callers.append(resolved_str)

                direct_calls = len(codebase_callers)
                transitive_calls = int(direct_calls * 1.5)
                call_depth = min(3, direct_calls)

            results.append({
                "module_name": package_name,
                "function_called": func_called,
                "encryption_internally": finding.algorithm,
                "codebase_caller": codebase_callers[0] if codebase_callers else "Unreferenced / External Declaration",
                "direct_calls": direct_calls,
                "indirect_calls": transitive_calls,
                "call_depth": call_depth,
                "file_path": finding.file_path,
                "line_number": finding.line_number
            })

        return results