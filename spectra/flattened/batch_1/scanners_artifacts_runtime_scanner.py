"""
spectra.scanners.artifacts.runtime_scanner
===============================================
Local runtime and process inspector. Gathers installed Python package inventories
and inspects active process executables and loaded shared libraries from local /proc
or a mounted container root filesystem.
"""

from dataclasses import dataclass, field
import importlib.metadata
import os
from pathlib import Path
from typing import Any, Dict, List, Optional
import yaml


@dataclass
class RuntimeFinding:
    """Represents runtime process or installed package evidence."""
    source_domain: str = "artifacts"
    artifact_type: str = "runtime_environment"
    file_path: str = ""
    finding_category: str = "installed_package"  # installed_package, process_executable, loaded_shared_library
    details: str = ""
    algorithm: str = "unknown"
    quantum_safe: bool = False
    shor_vulnerable: bool = True
    security_findings: List[Dict[str, str]] = field(default_factory=list)
    raw_metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "source_domain": self.source_domain,
            "artifact_type": self.artifact_type,
            "file_path": self.file_path,
            "finding_category": self.finding_category,
            "details": self.details,
            "algorithm": self.algorithm,
            "quantum_safe": self.quantum_safe,
            "shor_vulnerable": self.shor_vulnerable,
            "security_findings": self.security_findings,
            "raw_metadata": self.raw_metadata,
        }


class RuntimeScanner:
    """Inspects active local runtime state, installed packages, and process memory maps."""

    def __init__(self, rules_file: Optional[Path] = None, proc_path: Path = Path("/proc")):
        if rules_file is None:
            rules_file = Path(__file__).parent / "rules" / "runtime_patterns.yaml"
        self.rules = self._load_rules(rules_file)
        self.proc_path = proc_path

    def _load_rules(self, path: Path) -> Dict[str, Any]:
        if not path.is_file():
            return {}
        try:
            with open(path, "r", encoding="utf-8") as f:
                return yaml.safe_load(f) or {}
        except Exception:
            return {}

    def scan(self, target_dir: Optional[Path] = None) -> List[RuntimeFinding]:
        """Collects local Python packages and active process/library footprint."""
        findings: List[RuntimeFinding] = []
        findings.extend(self._scan_python_packages())
        findings.extend(self._scan_process_artifacts())
        return findings

    def _scan_python_packages(self) -> List[RuntimeFinding]:
        findings: List[RuntimeFinding] = []
        try:
            for dist in importlib.metadata.distributions():
                name = dist.metadata.get("Name") or dist.name
                version = dist.version
                try:
                    loc = str(dist.locate_file(""))
                except Exception:
                    loc = "unknown"

                # Flag crypto-capable packages found in active runtime
                is_crypto = name.lower() in {
                    "cryptography", "pycryptodome", "pycrypto", "pynacl", 
                    "pyopenssl", "python-jose", "jwcrypto", "bcrypt", "argon2-cffi"
                }

                findings.append(RuntimeFinding(
                    source_domain="artifacts",
                    artifact_type="runtime_environment",
                    file_path=loc,
                    finding_category="installed_package",
                    details=f"Active Python package installed: {name} v{version}",
                    algorithm=name,
                    quantum_safe=False,
                    shor_vulnerable=is_crypto,
                    security_findings=[{
                        "issue": f"Active package dependency present in runtime environment: {name} ({version})",
                        "severity": "LOW"
                    }],
                    raw_metadata={"package_name": name, "version": version, "installed_path": loc}
                ))
        except Exception:
            pass
        return findings

    def _scan_process_artifacts(self) -> List[RuntimeFinding]:
        findings: List[RuntimeFinding] = []
        if not self.proc_path.exists():
            return findings

        artifacts: Dict[str, Dict[str, Any]] = {}
        try:
            for pid in os.listdir(self.proc_path):
                if not pid.isdigit():
                    continue
                
                # 1. Process Executable
                exe_link = self.proc_path / pid / "exe"
                try:
                    executable = os.readlink(str(exe_link))
                    item = artifacts.setdefault(executable, {
                        "path": executable, "role": "process_executable", "pids": []
                    })
                    if pid not in item["pids"]:
                        item["pids"].append(pid)
                except OSError:
                    pass

                # 2. Loaded Shared Libraries (.so) via maps
                maps_file = self.proc_path / pid / "maps"
                try:
                    if maps_file.exists():
                        for line in maps_file.read_text(encoding="utf-8", errors="replace").splitlines():
                            fields = line.rstrip().split(None, 5)
                            mapped = fields[5] if len(fields) == 6 else ""
                            if ".so" not in mapped or mapped.startswith("["):
                                continue
                            item = artifacts.setdefault(mapped, {
                                "path": mapped, "role": "shared_library", "pids": []
                            })
                            if pid not in item["pids"]:
                                item["pids"].append(pid)
                except OSError:
                    pass
        except Exception:
            pass

        for path, info in artifacts.items():
            findings.append(RuntimeFinding(
                source_domain="artifacts",
                artifact_type="runtime_environment",
                file_path=path,
                finding_category="process_executable" if info["role"] == "process_executable" else "loaded_shared_library",
                details=f"Active runtime {info['role']}: {path} (PIDs: {', '.join(info['pids'][:5])})",
                algorithm="Native-Binary",
                quantum_safe=False,
                shor_vulnerable=True,
                security_findings=[],
                raw_metadata={"role": info["role"], "pids": info["pids"]}
            ))

        return findings