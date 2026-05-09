"""MySQL Scanner - Lite-mode discovery of MySQL/MariaDB instances.

This scanner avoids mandatory client dependencies and instead detects
databases via network listeners, processes, and configuration files.
"""

import re
from dataclasses import dataclass, field

from server_doctor.connector.ssh import SSHConnector
from server_doctor.model.server import (
    CapabilityLevel,
    CapabilityReason,
    ServiceState,
    ServiceStatus,
)


@dataclass
class MySQLScanResult:
    """Raw MySQL scan results."""

    status: ServiceStatus
    databases: list[str] = field(default_factory=list)
    config_detected: bool = False
    bind_addresses: list[str] = field(default_factory=list)


class MySQLScanner:
    """Scanner for MySQL/MariaDB services.

    Collects:
    - Running instances via `ss` and `ps`
    - Non-standard ports from process arguments
    - Configuration presence and socket paths
    """

    CONFIG_PATHS = [
        "/etc/mysql/my.cnf",
        "/etc/mysql/mysql.conf.d/mysqld.cnf",
        "/etc/my.cnf",
    ]
    
    SOCKET_PATHS = [
        "/var/run/mysqld/mysqld.sock",
        "/var/lib/mysql/mysql.sock",
    ]

    def __init__(self, ssh: SSHConnector) -> None:
        self.ssh = ssh

    def scan(self) -> MySQLScanResult:
        """Perform lite MySQL scan.

        Returns:
            MySQLScanResult with all collected data.
        """
        # 1. Detect running processes and ports
        ports, version, state, bind_addresses = self._find_running_instances()
        
        # 2. Check config presence
        config_present = self._check_config_presence()
        
        # 3. Determine capability
        # We consider it FULL if we found at least one of (process, port, config, socket)
        # Even if we can't 'query' it, we are 'FULL' in our 'LITE' capacity.
        capability = CapabilityLevel.FULL
        reason = None
        
        if state == ServiceState.NOT_INSTALLED and not config_present:
            capability = CapabilityLevel.NONE
            reason = CapabilityReason.BINARY_MISSING
        elif state == ServiceState.STOPPED:
            capability = CapabilityLevel.LIMITED
            reason = None # It's just stopped

        return MySQLScanResult(
            status=ServiceStatus(
                capability=capability,
                state=state,
                reason=reason,
                version=version,
                listening_ports=ports,
            ),
            config_detected=config_present,
            bind_addresses=bind_addresses,
        )

    def _find_running_instances(self) -> tuple[list[int], str | None, ServiceState, list[str]]:
        """Find running mysqld instances and their ports."""
        ports: list[int] = []
        bind_addresses: list[str] = []
        version: str | None = None
        state = ServiceState.NOT_INSTALLED

        # Check processes
        ps_result = self.ssh.run(
            "timeout 3s sh -lc 'ps aux | grep [m]ysqld'",
            timeout=5,
        )
        if ps_result.success:
            state = ServiceState.RUNNING
            # Try to grab version from binary
            v_cmd = "mysqld --version 2>/dev/null || mysql --version 2>/dev/null"
            v_res = self.ssh.run(f"timeout 3s sh -lc '{v_cmd}'", timeout=5)
            if v_res.success:
                # Version 8.0.34, or MariaDB 10.6.14
                match = re.search(r"(\d+\.\d+\.\d+)", v_res.stdout)
                if match:
                    version = match.group(1)

            # Check network listeners for non-standard ports
            ss_result = self.ssh.run(
                "timeout 3s sh -lc 'ss -lntp | grep mysqld'",
                timeout=5,
            )
            if ss_result.success:
                for line in ss_result.stdout.splitlines():
                    parts = line.split()
                    if len(parts) < 5:
                        continue

                    local_addr = parts[4]
                    addr = local_addr
                    port = None

                    if local_addr.startswith("[") and "]:" in local_addr:
                        host_part, port_part = local_addr.rsplit("]:", 1)
                        addr = host_part.lstrip("[")
                        if port_part.isdigit():
                            port = int(port_part)
                    elif ":" in local_addr:
                        host_part, port_part = local_addr.rsplit(":", 1)
                        addr = host_part
                        if port_part.isdigit():
                            port = int(port_part)

                    if port is not None:
                        ports.append(port)
                        bind_addresses.append(addr)
            
            # If ss failed or yielded nothing, check process args for --port
            if not ports:
                match = re.search(r"--port=(\d+)", ps_result.stdout)
                if match:
                    ports.append(int(match.group(1)))
                else:
                    # Default
                    ports.append(3306)
                bind_addresses.append("127.0.0.1")
        else:
            # Check if installed but stopped
            if self.ssh.run(
                "command -v mysqld",
                timeout=3,
                use_sudo=False,
            ).success or self.ssh.run(
                "timeout 3s systemctl status mysql",
                timeout=5,
            ).success:
                state = ServiceState.STOPPED

        return sorted(list(set(ports))), version, state, sorted(list(set(bind_addresses)))

    def _check_config_presence(self) -> bool:
        """Check if MySQL config files exist."""
        for path in self.CONFIG_PATHS:
            if self.ssh.run(f"test -f {path}", timeout=3).success:
                return True
        return False
