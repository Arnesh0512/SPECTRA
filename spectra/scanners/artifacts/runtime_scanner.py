"""
spectra.scanners.artifacts.runtime_scanner
===============================================
Dynamic runtime shared library inspector with Docker-aware process isolation.
Audits active loaded dynamic link libraries (.dll, .so, .dylib) mapped into 
process memory for Container C1 or the local host machine, ignoring Container C2.
"""

import os
import socket
import http.client
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Set
import yaml
import psutil


class UnixHTTPConnection(http.client.HTTPConnection):
    """Helper class to communicate with Docker daemon over Unix socket without external SDKs."""
    def __init__(self, unix_socket_path: str = "/var/run/docker.sock"):
        super().__init__("localhost")
        self.unix_socket_path = unix_socket_path

    def connect(self):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.connect(self.unix_socket_path)


@dataclass
class RuntimeFinding:
    """Represents runtime shared library or DLL evidence from process memory maps."""
    source_domain: str = "artifacts"
    artifact_type: str = "runtime_environment"
    file_path: str = ""
    finding_category: str = "loaded_shared_library"
    details: str = ""
    algorithm: str = "Native-Binary"
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
    """Intelligently inspects process memory maps for shared libraries / DLLs (.so, .dll, .dylib) 
    targeting Container C1, local machine runtime, while strictly ignoring Container C2."""

    def __init__(self, rules_file: Optional[Path] = None):
        if rules_file is None:
            rules_file = Path(__file__).parent / "rules" / "runtime_patterns.yaml"
        self.rules = self._load_rules(rules_file)
        self.target_extensions = tuple(self.rules.get("target_shared_object_extensions", [".so", ".dll", ".dylib"]))

    def _load_rules(self, path: Path) -> Dict[str, Any]:
        if not path.is_file():
            return {}
        try:
            with open(path, "r", encoding="utf-8") as f:
                return yaml.safe_load(f) or {}
        except Exception:
            return {}

    def _get_target_pids(self, target_dir: Optional[Path]) -> Optional[Set[int]]:
        """Resolves target PIDs using Docker socket inspection if scanning Container C1, 
        or returns None for host-wide scanning (excluding C2)."""
        if not target_dir:
            return None

        docker_socket_path = "/var/run/docker.sock"
        if not os.path.exists(docker_socket_path):
            return None

        try:
            conn = UnixHTTPConnection(docker_socket_path)
            conn.request("GET", "/containers/json")
            resp = conn.getresponse()
            if resp.status != 200:
                return None
            
            containers = json.loads(resp.read().decode())
            target_str = str(target_dir.resolve()).lower()

            target_container_id = None
            for container in containers:
                # Check if target_dir matches container mounts or root paths
                inspect_conn = UnixHTTPConnection(docker_socket_path)
                inspect_conn.request("GET", f"/containers/{container['Id']}/json")
                inspect_resp = inspect_conn.getresponse()
                if inspect_resp.status == 200:
                    c_info = json.loads(inspect_resp.read().decode())
                    # Check mounts
                    for mount in c_info.get("Mounts", []):
                        destination = mount.get("Destination", "").lower()
                        source = mount.get("Source", "").lower()
                        if destination in target_str or source in target_str or target_str in destination:
                            target_container_id = container['Id']
                            break
                if target_container_id:
                    break

            if target_container_id:
                # Fetch state pid of target container C1
                inspect_conn = UnixHTTPConnection(docker_socket_path)
                inspect_conn.request("GET", f"/containers/{target_container_id}/json")
                inspect_resp = inspect_conn.getresponse()
                if inspect_resp.status == 200:
                    c_info = json.loads(inspect_resp.read().decode())
                    root_pid = c_info.get("State", {}).get("Pid", 0)
                    if root_pid > 0:
                        # Collect root PID and all its child processes for C1
                        valid_pids = {root_pid}
                        try:
                            parent = psutil.Process(root_pid)
                            for child in parent.children(recursive=True):
                                valid_pids.add(child.pid)
                        except (psutil.NoSuchProcess, psutil.AccessDenied):
                            pass
                        return valid_pids
        except Exception:
            pass

        return None

    def scan(self, target_dir: Optional[Path] = None) -> List[RuntimeFinding]:
        """Collects active loaded shared libraries and DLLs from memory maps based on target isolation."""
        findings: List[RuntimeFinding] = []
        artifacts: Dict[str, Dict[str, Any]] = {}

        # Determine target process scope (Container C1 PIDs vs Host PIDs minus C2)
        target_pids = self._get_target_pids(target_dir)
        current_c2_pid = os.getpid()
        c2_process_tree = set()
        try:
            c2_proc = psutil.Process(current_c2_pid)
            c2_process_tree.add(c2_proc.pid)
            for child in c2_proc.children(recursive=True):
                c2_process_tree.add(child.pid)
        except Exception:
            pass

        try:
            for proc in psutil.process_iter(['pid', 'name', 'memory_maps']):
                try:
                    pinfo = proc.info
                    pid = pinfo.get('pid')
                    if not pid:
                        continue

                    # Rule 1: If scanning C1, strictly look only at C1's PIDs
                    if target_pids is not None and pid not in target_pids:
                        continue

                    # Rule 2: If scanning local/host, explicitly ignore C2 container processes
                    if target_pids is None and pid in c2_process_tree:
                        continue

                    pid_str = str(pid)
                    mmap_func = getattr(proc, 'memory_maps', None)
                    if mmap_func:
                        for m in mmap_func():
                            path = getattr(m, 'path', '')
                            if path and any(path.lower().endswith(ext) for ext in self.target_extensions):
                                lib_item = artifacts.setdefault(path, {
                                    "path": path, "pids": []
                                })
                                if pid_str not in lib_item["pids"]:
                                    lib_item["pids"].append(pid_str)
                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                    continue
        except Exception:
            pass

        for path, info in artifacts.items():
            findings.append(RuntimeFinding(
                source_domain="artifacts",
                artifact_type="runtime_environment",
                file_path=path,
                finding_category="loaded_shared_library",
                details=f"Active loaded shared library / DLL: {path} (PIDs: {', '.join(info['pids'][:5])})",
                algorithm="Native-Binary",
                quantum_safe=False,
                shor_vulnerable=True,
                security_findings=[],
                raw_metadata={"role": "shared_library", "pids": info["pids"]}
            ))

        return findings