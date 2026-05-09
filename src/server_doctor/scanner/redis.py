"""Redis Scanner - Detects Redis instances and audits configuration.

This scanner identifies running Redis processes, extracts their configuration
paths, and checks for critical security settings like authentication and binding.
"""

import re
from dataclasses import dataclass, field

from server_doctor.connector.ssh import SSHConnector
from server_doctor.model.server import (
    CapabilityLevel,
    CapabilityReason,
    RedisInstance,
    ServiceState,
    ServiceStatus,
)


@dataclass
class RedisScanResult:
    """Raw Redis scan results."""

    status: ServiceStatus
    instances: list[RedisInstance] = field(default_factory=list)


class RedisScanner:
    """Scanner for Redis instances.

    Collects:
    - Listening ports and binding addresses (via ss)
    - Config file location (via ps)
    - Authentication status (via config parsing)
    """

    def __init__(self, ssh: SSHConnector) -> None:
        self.ssh = ssh

    def scan(self) -> RedisScanResult:
        """Perform full Redis scan."""
        instances = []
        
        # 1. Detect capabilities / installed
        if not self.ssh.run("which redis-server").success:
            return RedisScanResult(
                status=ServiceStatus(
                    capability=CapabilityLevel.NONE,
                    state=ServiceState.NOT_INSTALLED
                )
            )

        # 2. Find running processes to get config paths
        # ps aux output: user pid ... command
        # redis-server *:6379 OR redis-server /etc/redis/redis.conf
        ps_cmd = "ps aux | grep redis-server | grep -v grep"
        ps_result = self.ssh.run(ps_cmd)
        
        config_map = {}  # PID -> Config Path
        if ps_result.success:
            for line in ps_result.stdout.splitlines():
                parts = line.split()
                if len(parts) > 10:
                    pid = int(parts[1])
                    # cmdline starts around index 10 usually, strictly it's the last part
                    # but arguments might follow.
                    # We are looking for the config file argument, which usually is the first arg
                    # that doesn't start with -.
                    # Example: /usr/bin/redis-server 127.0.0.1:6379
                    # Example: /usr/bin/redis-server /etc/redis/redis.conf
                    
                    args = parts[10:]
                    # If the command is just "redis-server", look at args
                    # If command is full path: "/usr/bin/redis-server", look at args
                    
                    config_path = None
                    for arg in args:
                        if arg.endswith(".conf") and arg.startswith("/"):
                            config_path = arg
                            break
                    
                    if config_path:
                        config_map[pid] = config_path

        # 3. Find listening ports via ss
        # output: Netid State Recv-Q Send-Q Local Address:Port Peer Address:Port Process
        # tcp LISTEN 0 511 127.0.0.1:6379 0.0.0.0:* users:(("redis-server",pid=123,fd=6))
        ss_cmd = "ss -lntp | grep redis"
        ss_result = self.ssh.run(ss_cmd)
        
        if ss_result.success:
            for line in ss_result.stdout.splitlines():
                if "redis-server" not in line:
                    continue
                
                parts = line.split()
                # Local Address:Port is usually at index 4 (0-based)
                # But whitespace split works safely
                local_addr_port = parts[4]
                if ":" in local_addr_port:
                    addr_str, port_str = local_addr_port.rsplit(":", 1)
                    port = int(port_str)
                    
                    # Extract PID to match config
                    pid = None
                    pid_match = re.search(r"pid=(\d+)", line)
                    if pid_match:
                        pid = int(pid_match.group(1))
                    
                    config_path = config_map.get(pid)
                    
                    # Check auth and config
                    auth_enabled = None
                    protected_mode = False
                    
                    if config_path:
                        auth_enabled, protected_mode = self._check_config(config_path)
                    
                    # Check if already added (dual stack IPv4/IPv6 might show up twice)
                    # We merge bind addresses
                    existing = next((i for i in instances if i.port == port), None)
                    if existing:
                        if addr_str not in existing.bind_addresses:
                            existing.bind_addresses.append(addr_str)
                    else:
                        instances.append(RedisInstance(
                            port=port,
                            state=ServiceState.RUNNING,
                            config_path=config_path,
                            auth_enabled=auth_enabled,
                            bind_addresses=[addr_str],
                            protected_mode=protected_mode
                        ))

        return RedisScanResult(
            status=ServiceStatus(
                capability=CapabilityLevel.FULL,
                state=ServiceState.RUNNING if instances else ServiceState.STOPPED
            ),
            instances=instances
        )

    def _check_config(self, path: str) -> tuple[bool | None, bool]:
        """Parse redis config for auth and protected-mode.
        
        Returns:
            (auth_enabled (Tri-state), protected_mode)
        """
        content = self.ssh.read_file(path)
        if not content:
            return None, False  # Unknown
            
        auth_found = False
        protected = False
        
        # Simple parsing handling includes? Usually simple grep is enough or regex.
        # "requirepass foobar"
        # "user default on >password ..." (ACL)
        # "protected-mode yes"
        
        # Check for requirepass
        if re.search(r"^\s*requirepass\s+\S+", content, re.MULTILINE):
            auth_found = True
        
        # Check for ACL user default with password
        # pattern: user default ... >(password hash or plain)
        if re.search(r"^\s*user\s+default\s+.*>\S+", content, re.MULTILINE):
            auth_found = True
            
        # Check for aclfile
        if re.search(r"^\s*aclfile\s+\S+", content, re.MULTILINE):
            # If aclfile is used, we assume auth is managed there (likely enabled)
            # but ideally we'd check the aclfile. For now, treat as "True" or "Unknown"?
            # Plan says "requirepass OR user default ... OR aclfile" -> True
            auth_found = True

        if re.search(r"^\s*protected-mode\s+yes", content, re.MULTILINE):
            protected = True
            
        return auth_found, protected
