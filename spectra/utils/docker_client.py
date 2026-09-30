"""
spectra.utils.docker_client
===========================
Lightweight, zero-dependency Docker Engine API client using Unix Domain Sockets (/var/run/docker.sock).
Enables Spectra to discover, inspect, and extract codebases directly from running Docker containers
without requiring host volume mounts or external Docker SDK dependencies.
"""

import http.client
import io
import json
import logging
import os
import shutil
import socket
import tarfile
import urllib.parse
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger("spectra.docker_client")


class UnixSocketHTTPConnection(http.client.HTTPConnection):
    """HTTPConnection subclass that communicates over a Unix domain socket."""

    def __init__(self, socket_path: str = "/var/run/docker.sock", timeout: int = 180):
        super().__init__("localhost", timeout=timeout)
        self.socket_path = socket_path

    def connect(self) -> None:
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.settimeout(self.timeout)
        self.sock.connect(self.socket_path)


class DockerContainerClient:
    """Client for inspecting and extracting files from running Docker containers via Docker Socket."""

    def __init__(self, socket_path: str = "/var/run/docker.sock"):
        self.socket_path = socket_path

    def is_available(self) -> bool:
        """Check if Docker socket exists and is accessible."""
        return os.path.exists(self.socket_path) and os.access(self.socket_path, os.R_OK | os.W_OK)

    def _request(self, method: str, endpoint: str) -> Tuple[int, bytes, Dict[str, str]]:
        """Perform a raw HTTP request to the Docker daemon over unix socket."""
        conn = UnixSocketHTTPConnection(self.socket_path)
        try:
            conn.request(method, endpoint, headers={"Host": "localhost"})
            resp = conn.getresponse()
            headers = {k.lower(): v for k, v in resp.getheaders()}
            data = resp.read()
            return resp.status, data, headers
        finally:
            conn.close()

    def list_containers(self, all: bool = False) -> List[Dict[str, Any]]:
        """List running containers from Docker daemon."""
        endpoint = f"/v1.43/containers/json?all={'1' if all else '0'}"
        status, data, _ = self._request("GET", endpoint)
        if status != 200:
            raise RuntimeError(f"Docker API error ({status}): {data.decode('utf-8', errors='replace')}")
        return json.loads(data.decode("utf-8"))

    def get_container_info(self, container_id_or_name: str) -> Dict[str, Any]:
        """Fetch container JSON metadata from Docker Engine API."""
        safe_name = container_id_or_name.strip()
        endpoint = f"/v1.43/containers/{safe_name}/json"
        status, data, _ = self._request("GET", endpoint)
        if status == 404:
            raise ValueError(f"Docker container '{container_id_or_name}' not found on host daemon.")
        if status != 200:
            raise RuntimeError(f"Docker API error ({status}): {data.decode('utf-8', errors='replace')}")
        return json.loads(data.decode("utf-8"))

    def extract_container_path(
        self,
        container_id_or_name: str,
        container_path: str,
        dest_dir: Optional[Path] = None,
    ) -> Path:
        """
        Extracts a path from inside a running container using Docker Archive API.
        Returns the local Path containing the extracted files.
        """
        safe_name = container_id_or_name.strip()
        encoded_path = urllib.parse.quote(container_path)
        endpoint = f"/v1.43/containers/{safe_name}/archive?path={encoded_path}"

        conn = UnixSocketHTTPConnection(self.socket_path)
        try:
            conn.request("GET", endpoint, headers={"Host": "localhost"})
            resp = conn.getresponse()
            if resp.status == 404:
                raise FileNotFoundError(
                    f"Path '{container_path}' not found inside container '{container_id_or_name}'."
                )
            if resp.status != 200:
                err_msg = resp.read().decode("utf-8", errors="replace")
                raise RuntimeError(f"Docker archive error ({resp.status}): {err_msg}")

            clean_name = safe_name.replace("/", "_").strip("_")
            if dest_dir is None:
                dest_dir = Path("/tmp/spectra_containers") / clean_name

            # Reset destination folder to guarantee fresh sync
            if dest_dir.exists():
                shutil.rmtree(dest_dir, ignore_errors=True)
            dest_dir.mkdir(parents=True, exist_ok=True)

            # Read tar stream and unpack
            tar_bytes = resp.read()
            with tarfile.open(fileobj=io.BytesIO(tar_bytes), mode="r:*") as tar:
                for member in tar.getmembers():
                    member.name = member.name.lstrip("/")
                try:
                    tar.extractall(path=dest_dir, filter="data")
                except TypeError:
                    tar.extractall(path=dest_dir)

            base_name = Path(container_path.rstrip("/")).name
            extracted_sub = dest_dir / base_name
            if extracted_sub.is_dir():
                return extracted_sub
            return dest_dir
        finally:
            conn.close()

    def resolve_container_perimeter(
        self,
        container_id_or_name: str,
        container_path: Optional[str] = None,
    ) -> Tuple[Path, Dict[str, Any]]:
        """
        Resolves the filesystem path for the target container.
        1. If host PID tree (/proc/<pid>/root) is accessible, binds directly with zero copy.
        2. Otherwise, transparently streams the directory tarball via Docker Archive API.
        """
        info = self.get_container_info(container_id_or_name)
        pid = info.get("State", {}).get("Pid", 0)

        # Dynamically default to the container's home directory
        if not container_path:
            env_vars = dict(e.split("=", 1) for e in info.get("Config", {}).get("Env", []) if "=" in e)
            c_user = info.get("Config", {}).get("User", "")
            c_home = env_vars.get("HOME")
            if not c_home:
                c_home = f"/home/{c_user}" if (c_user and c_user != "root") else "/root"
            container_path = c_home

        # 1. Fast-path: Check if direct host proc filesystem is mounted and accessible
        if pid > 0:
            proc_root_path = Path(f"/proc/{pid}/root{container_path}")
            if proc_root_path.exists() and os.access(proc_root_path, os.R_OK):
                logger.info(f"Direct host proc perimeter active at {proc_root_path} (PID: {pid})")
                return proc_root_path, info

        # 2. Archive API streaming fallback (100% reliable across any Docker setup)
        logger.info(f"Extracting container archive for {container_id_or_name}:{container_path}")
        extracted_path = self.extract_container_path(container_id_or_name, container_path)
        return extracted_path, info
