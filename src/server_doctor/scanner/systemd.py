"""Systemd Scanner - Collects service information via systemctl or procfs.

This scanner detects systemd services, their states, and restart counts.
It supports a FULL mode (via systemctl) and a LIMITED fallback mode (via /proc).
"""

import re
from dataclasses import dataclass, field

from server_doctor.connector.ssh import SSHConnector
from server_doctor.model.server import (
    CapabilityLevel,
    CapabilityReason,
    ServiceState,
    ServiceStatus,
    SystemdService,
)


@dataclass
class SystemdScanResult:
    """Raw Systemd scan results."""

    status: ServiceStatus
    services: list[SystemdService] = field(default_factory=list)


class SystemdScanner:
    """Scanner for Systemd services.

    Collects:
    - Service state (active, failed, etc.)
    - Restart counts (NRestarts or heuristic)
    - Main PID and ExecStart
    """

    def __init__(self, ssh: SSHConnector) -> None:
        self.ssh = ssh

    def scan(self) -> SystemdScanResult:
        """Perform full Systemd scan."""
        # 1. Check capability
        if self._has_systemctl():
            return self._scan_full()
        
        # 2. Fallback to limited scan
        return self._scan_limited()

    def _has_systemctl(self) -> bool:
        """Check if systemctl is available."""
        return self.ssh.run("which systemctl").success

    def _scan_full(self) -> SystemdScanResult:
        """Scan using systemctl (FULL capability)."""
        services = []
        
        # List all services
        # output format: unit loaded active sub description
        cmd = "systemctl list-units --type=service --all --no-pager --no-legend --plain"
        result = self.ssh.run(cmd)
        
        if not result.success:
            return SystemdScanResult(
                status=ServiceStatus(
                    capability=CapabilityLevel.LIMITED,
                    reason=CapabilityReason.PERMISSION_DENIED,
                    state=ServiceState.UNKNOWN
                )
            )

        # Parse list-units output
        units_to_inspect = []
        for line in result.stdout.splitlines():
            parts = line.split(maxsplit=4)
            if len(parts) >= 4:
                unit_name = parts[0]
                state = parts[2]
                substate = parts[3]
                
                # We are interested in active, failed, or activating services
                if state in ("active", "failed", "activating") or substate in ("failed", "auto-restart"):
                    units_to_inspect.append(unit_name)
                    # Basic info first
                    services.append(SystemdService(
                        name=unit_name,
                        state=state,
                        substate=substate
                    ))

        # Enrich with detailed properties (batching would be ideal but systemctl show handles multiple units)
        if units_to_inspect:
            self._enrich_services(services, units_to_inspect)

        return SystemdScanResult(
            status=ServiceStatus(
                capability=CapabilityLevel.FULL,
                state=ServiceState.RUNNING,
                version=self._get_systemd_version()
            ),
            services=services
        )

    def _enrich_services(self, services: list[SystemdService], unit_names: list[str]) -> None:
        """Fetch detailed properties for services."""
        # Split into chunks to avoid command line length limits
        chunk_size = 50
        for i in range(0, len(unit_names), chunk_size):
            chunk = unit_names[i:i + chunk_size]
            # Fetch MainPID, NRestarts, ExecStart, Id
            # Note: NRestarts might not be available on old systemd versions
            cmd = f"systemctl show {' '.join(chunk)} --property=Id,MainPID,NRestarts,ExecStart,ActiveEnterTimestampMonotonic --no-pager"
            result = self.ssh.run(cmd)
            
            if result.success:
                self._parse_show_output(services, result.stdout)

    def _parse_show_output(self, services: list[SystemdService], output: str) -> None:
        """Parse systemctl show output."""
        current_unit = {}
        
        # Helper to apply properties to the matching service
        def apply_properties(props: dict):
            if not props.get("Id"):
                return
            
            for service in services:
                if service.name == props["Id"]:
                    service.main_pid = int(props["MainPID"]) if props.get("MainPID") and props["MainPID"] != "0" else None
                    
                    # Restart count logic
                    if props.get("NRestarts"):
                        try:
                            service.restart_count = int(props["NRestarts"])
                        except ValueError:
                            pass
                    
                    # Heuristic for ExecStart (it looks like: { path=/usr/sbin/nginx ; argv[]=/usr/sbin/nginx -g daemon on; master_process on; ; ... })
                    if props.get("ExecStart"):
                        # Extract useful part
                        match = re.search(r"path=([^ ;]+)", props["ExecStart"])
                        if match:
                            service.exec_start = match.group(1)
                    break

        for line in output.splitlines():
            if not line.strip():
                # Empty line separator between units (sometimes) or just end of block
                if current_unit:
                    apply_properties(current_unit)
                    current_unit = {}
                continue
                
            if "=" in line:
                key, val = line.split("=", 1)
                current_unit[key] = val
        
        # Apply last one
        if current_unit:
            apply_properties(current_unit)

    def _scan_limited(self) -> SystemdScanResult:
        """Scan using /proc (LIMITED capability)."""
        # This is a best-effort fallback
        services = []
        
        # We can't really list systemd units without systemctl/dbus.
        # But we can look for common service names in process list? 
        # Actually, if systemctl is missing, it might not even use systemd.
        # But maybe permission denied?
        # For now, return limited status.
        
        return SystemdScanResult(
            status=ServiceStatus(
                capability=CapabilityLevel.LIMITED,
                reason=CapabilityReason.PERMISSION_DENIED,
                state=ServiceState.UNKNOWN
            ),
            services=services
        )

    def _get_systemd_version(self) -> str | None:
        """Get systemd version."""
        res = self.ssh.run("systemctl --version | head -n 1")
        if res.success:
            return res.stdout.split()[-1].replace("(", "").replace(")", "")
        return None
