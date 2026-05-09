"""Nginx Collector - Orchestrates host and docker discovery of Nginx.

This module implements the "Runtime-First" discovery strategy to find 
Nginx whether it is running on the host or inside a Docker container.
"""

import re
import json
from dataclasses import dataclass, field
from server_doctor.connector.ssh import SSHConnector
from server_doctor.model.server import CapabilityLevel, CapabilityReason, ServiceStatus, ServiceState


@dataclass
class CollectorResult:
    """Result of the Nginx collection process."""
    mode: str = "NONE"  # HOST, DOCKER, NONE
    container_id: str | None = None
    config_dump: str = ""
    version: str = ""
    status: ServiceStatus = field(default_factory=lambda: ServiceStatus(capability=CapabilityLevel.NONE))
    path_mapping: dict[str, str] = field(default_factory=dict)


class NginxCollector:
    """Orchestrator for Nginx discovery across Host and Docker."""

    def __init__(self, ssh: SSHConnector) -> None:
        self.ssh = ssh

    def collect(self) -> CollectorResult:
        """Discover and collect Nginx configuration.
        
        Tries host first, then falls back to Docker.
        """
        # 1. Try Host First
        host_result = self._collect_from_host()
        if host_result.mode != "NONE":
            return host_result

        # 2. Try Docker Fallback
        docker_result = self._collect_from_docker()
        if docker_result.mode != "NONE":
            return docker_result

        return host_result  # Return the host failure result (likely NONE)

    def _collect_from_host(self) -> CollectorResult:
        """Attempt to collect configuration from the host."""
        result = CollectorResult(mode="NONE")
        
        # Binary probing order
        binaries = ["nginx", "openresty", "nginx-debug"]
        
        found_binary = None
        for b in binaries:
            check = self.ssh.run(f"command -v {b}", timeout=5, use_sudo=False)
            if check.success:
                found_binary = b
                break
        
        if not found_binary:
            result.status.reason = CapabilityReason.BINARY_MISSING
            result.status.state = ServiceState.NOT_INSTALLED
            return result

        # Try runtime truth (nginx -T)
        # Use sh -lc to ensure PATH etc.
        dump_result = self.ssh.run(
            f"timeout 12s sh -lc '{found_binary} -T 2>&1'",
            timeout=15,
        )
        if dump_result.exit_code == 0:
            result.mode = "HOST"
            result.config_dump = dump_result.stdout
            result.status.capability = CapabilityLevel.FULL
            result.status.state = ServiceState.RUNNING
            
            # Extract version
            v_result = self.ssh.run(f"{found_binary} -v 2>&1", timeout=5, use_sudo=False)
            if "nginx/" in v_result.stderr or "nginx/" in v_result.stdout:
                output = v_result.stderr or v_result.stdout
                result.version = output.split("nginx/")[1].split()[0].strip()
            
            return result
        
        # If -T failed but binary exists, maybe permissions?
        if "permission denied" in dump_result.stderr.lower():
            result.status.capability = CapabilityLevel.LIMITED
            result.status.reason = CapabilityReason.PERMISSION_DENIED
        else:
            result.status.capability = CapabilityLevel.NONE
            result.status.reason = CapabilityReason.UNKNOWN

        return result

    def _collect_from_docker(self) -> CollectorResult:
        """Attempt to discover Nginx inside Docker containers via heuristics."""
        # First check if docker is even functional
        docker_check = self.ssh.run("docker ps --format '{{.ID}}'", timeout=8)
        if not docker_check.success:
            return CollectorResult(mode="NONE")

        # Get detailed list for heuristic matching
        # Format: ID | Names | Ports | Image
        ps_result = self.ssh.run(
            "docker ps --format '{{.ID}}\t{{.Names}}\t{{.Ports}}\t{{.Image}}'",
            timeout=8,
        )
        if not ps_result.success or not ps_result.stdout:
            return CollectorResult(mode="NONE")

        candidates = []
        for line in ps_result.stdout.strip().split("\n"):
            parts = line.split("\t")
            if len(parts) < 4:
                continue
            
            cid, name, ports, image = parts
            weight = 0
            
            # Heuristic 1: Host Port binding (Best)
            if "0.0.0.0:80->" in ports or ":::80->" in ports:
                weight += 10
            if "0.0.0.0:443->" in ports or ":::443->" in ports:
                weight += 10
            
            # Heuristic 2: Name/Image signals
            signals = ["nginx", "proxy", "gateway", "reverse", "openresty"]
            if any(s in name.lower() for s in signals):
                weight += 5
            if any(s in image.lower() for s in signals):
                weight += 5
            
            # Heuristic 3: Exposed but not bound 80/443
            if "80/tcp" in ports:
                weight += 2
            if "443/tcp" in ports:
                weight += 2
                
            if weight > 0:
                candidates.append({
                    "id": cid,
                    "weight": weight,
                    "name": name
                })

        # Sort by weight descending
        candidates.sort(key=lambda x: x["weight"], reverse=True)

        for candidate in candidates:
            cid = candidate["id"]
            # Probe inside for nginx -T
            # Try multiple binaries inside container
            inner_binaries = ["nginx", "openresty", "/usr/sbin/nginx"]
            
            for b in inner_binaries:
                exec_cmd = f"timeout 12s docker exec {cid} sh -lc '{b} -T 2>&1'"
                exec_result = self.ssh.run(exec_cmd, timeout=15)
                
                if exec_result.exit_code == 0:
                    res = CollectorResult(mode="DOCKER", container_id=cid)
                    res.config_dump = exec_result.stdout
                    res.status.capability = CapabilityLevel.FULL
                    res.status.state = ServiceState.RUNNING
                    
                    # Get version from inside
                    v_cmd = f"docker exec {cid} {b} -v 2>&1"
                    v_res = self.ssh.run(v_cmd, timeout=5)
                    output = v_res.stderr or v_res.stdout
                    if "nginx/" in output:
                        res.version = output.split("nginx/")[1].split()[0].strip()
                    
                    # 3. Mount Correlation
                    res.path_mapping = self._detect_mounts(cid)
                    
                    return res

        return CollectorResult(mode="NONE")

    def _detect_mounts(self, cid: str) -> dict[str, str]:
        """Extract bind mounts to map container paths to host paths."""
        inspect_result = self.ssh.run(f"docker inspect {cid}", timeout=8)
        if not inspect_result.success:
            return {}
            
        try:
            data = json.loads(inspect_result.stdout)
            if not data or not isinstance(data, list):
                return {}
            
            mounts = data[0].get("Mounts", [])
            mapping = {}
            for m in mounts:
                if m.get("Type") == "bind":
                    src = m.get("Source")
                    dst = m.get("Destination")
                    if src and dst:
                        mapping[dst.rstrip("/")] = src.rstrip("/")
            return mapping
        except (json.JSONDecodeError, KeyError, IndexError):
            return {}
