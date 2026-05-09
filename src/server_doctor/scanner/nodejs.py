"""Node.js Scanner - Structured identification of Node.js processes.

This scanner collects running Node processes, maps them to listening ports,
and classifies them into dev-servers, SSR engines, or APIs.
"""

import re
from dataclasses import dataclass, field

from server_doctor.connector.ssh import SSHConnector
from server_doctor.model.server import (
    CapabilityLevel,
    CapabilityReason,
    NodeProcess,
    ServiceState,
    ServiceStatus,
)


@dataclass
class NodeScanResult:
    """Raw Node.js scan results."""

    status: ServiceStatus
    processes: list[NodeProcess] = field(default_factory=list)


class NodeScanner:
    """Scanner for Node.js runtime and processes.

    Collects:
    - Global Node/NPM versions
    - Running processes with CWD and command line
    - Port mapping via `ss`
    """

    def __init__(self, ssh: SSHConnector) -> None:
        self.ssh = ssh

    def scan(self) -> NodeScanResult:
        """Perform full Node.js scan.

        Returns:
            NodeScanResult with all collected data.
        """
        # 1. Detect global node presence
        version = self._get_global_version()
        state = ServiceState.NOT_INSTALLED
        if version:
            state = ServiceState.STOPPED # Assume stopped unless we find processes

        # 2. Find running processes
        processes = self._find_processes()
        if processes:
            state = ServiceState.RUNNING

        # 3. Determine capability
        capability = CapabilityLevel.FULL if version or processes else CapabilityLevel.NONE
        reason = CapabilityReason.BINARY_MISSING if not (version or processes) else None

        return NodeScanResult(
            status=ServiceStatus(
                capability=capability,
                state=state,
                reason=reason,
                version=version,
            ),
            processes=processes
        )

    def _get_global_version(self) -> str | None:
        """Get global node version."""
        res = self.ssh.run("node -v", timeout=2)
        if res.success:
            return res.stdout.strip().lstrip("v")
        return None

    def _find_processes(self) -> list[NodeProcess]:
        """Find running node processes and enrich with CWD and ports."""
        processes: list[NodeProcess] = []
        
        # Get all node processes
        ps_res = self.ssh.run("ps -Ao pid,cmd | grep [n]ode", timeout=2)
        if not ps_res.success:
            return []

        # Map ports to PIDs
        port_map = self._get_port_pid_map()

        pids = []
        for line in ps_res.stdout.strip().split("\n"):
            line = line.strip()
            if not line:
                continue
            parts = line.split(None, 1)
            if len(parts) >= 2:
                try:
                    pids.append((int(parts[0]), parts[1]))
                except ValueError:
                    continue

        if not pids:
            return []

        # Batch get CWDs and Container IDs
        cwd_map = {}
        container_map = {}
        pid_list = [str(p[0]) for p in pids]
        
        # Get CWD
        cwd_res = self.ssh.run(f"ls -l " + " ".join([f"/proc/{p}/cwd" for p in pid_list]), timeout=2)
        if cwd_res.success:
            for line in cwd_res.stdout.strip().split("\n"):
                match = re.search(r"/proc/(\d+)/cwd\s+->\s+(.+)", line)
                if match:
                    cwd_map[int(match.group(1))] = match.group(2)
        
        # Get Container ID from cgroup
        cgroup_res = self.ssh.run(f"grep 'docker' " + " ".join([f"/proc/{p}/cgroup" for p in pid_list]), timeout=2)
        if cgroup_res.success:
            for line in cgroup_res.stdout.strip().split("\n"):
                # Matches either host-view (with filename) or container-view (no filename)
                # v1: /proc/123/cgroup:1:name=systemd:/docker/ID...
                # v2: /proc/123/cgroup:0::/system.slice/docker-ID.scope
                # or just: 0::/system.slice/docker-ID.scope
                match = re.search(r"(?:/proc/(\d+)/cgroup:)?.*docker[/-]([a-f0-9]+)", line)
                if match:
                    pid = int(match.group(1)) if match.group(1) else pids[0][0] # Fallback for single-file grep
                    container_map[pid] = match.group(2)

        for pid, cmd in pids:
            processes.append(NodeProcess(
                pid=pid,
                cmdline=cmd,
                cwd=cwd_map.get(pid, "unknown"),
                container_id=container_map.get(pid),
                listening_ports=port_map.get(pid, [])
            ))

        return processes

    def _get_port_pid_map(self) -> dict[int, list[int]]:
        """Map listening ports to their PIDs via `ss`."""
        mapping: dict[int, list[int]] = {}
        
        # ss -lntp gives us: "LISTEN 0 128 127.0.0.1:3000 0.0.0.0:* users:(("node",pid=123,fd=45))"
        res = self.ssh.run("ss -lntp | grep node", timeout=2)
        if res.success:
            lines = res.stdout.strip().split("\n")
            for line in lines:
                # Extract PID and Port
                port_match = re.search(r":(\d+)\s+", line)
                pid_match = re.search(r"pid=(\d+)", line)
                
                if port_match and pid_match:
                    port = int(port_match.group(1))
                    pid = int(pid_match.group(1))
                    
                    if pid not in mapping:
                        mapping[pid] = []
                    mapping[pid].append(port)
        
        return mapping
