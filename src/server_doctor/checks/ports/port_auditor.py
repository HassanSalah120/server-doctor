"""Port Usage Analyzer.

Cross-references listening ports with Nginx proxy_pass targets to detect:
- PORT-1: Proxy target has no listening process (Critical)  
- PORT-2: Listening port not referenced by Nginx (Info)

Handles:
- proxy_pass http://upstream_name; → resolve upstream block
- proxy_pass http://127.0.0.1:8105; → direct IP:port
- proxy_pass http://unix:/path.sock; → validate socket exists (separate)
- fastcgi_pass unix:/run/php/php8.3-fpm.sock; → validate socket exists
"""

import re
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from server_doctor.checks import BaseCheck, CheckContext, register_check
from server_doctor.model.evidence import Evidence, Severity
from server_doctor.model.finding import Finding

if TYPE_CHECKING:
    from server_doctor.connector.ssh import SSHConnector


@dataclass
class ListeningPort:
    """A port listening on the system."""
    protocol: str  # tcp, udp
    address: str   # 0.0.0.0, 127.0.0.1, ::
    port: int
    pid: int | None = None
    program: str | None = None


@dataclass 
class ProxyTarget:
    """A proxy_pass or fastcgi_pass target."""
    target_type: str  # tcp, unix, upstream
    host: str | None = None
    port: int | None = None
    socket_path: str | None = None
    upstream_name: str | None = None
    source_file: str = ""
    line_number: int = 0
    location_path: str = ""


@register_check
class PortAuditor(BaseCheck):
    """Auditor for port usage analysis."""
    
    @property
    def category(self) -> str:
        return "ports"
    
    @property
    def requires_ssh(self) -> bool:
        return True
    
    def run(self, context: CheckContext) -> list[Finding]:
        """Run port analysis checks."""
        if not context.ssh:
            return []
        
        findings: list[Finding] = []
        
        # Collect data
        listening_ports = self._get_listening_ports(context.ssh)
        proxy_targets = self._extract_proxy_targets(context)
        
        # Run checks
        findings.extend(self._check_dead_proxy_targets(
            proxy_targets, listening_ports, context
        ))
        findings.extend(self._check_orphan_ports(
            listening_ports, proxy_targets, context
        ))
        
        return findings
    
    def _get_listening_ports(self, ssh: "SSHConnector") -> list[ListeningPort]:
        """Get all listening ports via ss or netstat."""
        ports: list[ListeningPort] = []
        
        # Try ss first (preferred)
        result = ssh.run("ss -tulpn 2>/dev/null || netstat -tulpn 2>/dev/null")
        
        if not result.stdout:
            return ports
        
        # Parse ss/netstat output
        # Format: tcp LISTEN 0 128 127.0.0.1:8105 0.0.0.0:* users:(("php-fpm8.3",pid=1234,fd=6))
        for line in result.stdout.strip().split("\n"):
            if "LISTEN" not in line:
                continue
            
            parts = line.split()
            if len(parts) < 5:
                continue
            
            # Extract local address (format: address:port)
            local_addr = None
            for i, part in enumerate(parts):
                if ":" in part and not part.startswith("users:"):
                    # Check if it looks like address:port
                    if re.match(r'[\d\.\:\[\]]+:\d+$', part) or re.match(r'\*:\d+$', part):
                        local_addr = part
                        break
            
            if not local_addr:
                continue
            
            # Parse address:port
            if local_addr.startswith("["):
                # IPv6: [::]:8080
                match = re.match(r'\[([^\]]*)\]:(\d+)', local_addr)
                if match:
                    addr = match.group(1)
                    port_num = int(match.group(2))
                else:
                    continue
            else:
                # IPv4 or wildcard
                addr_parts = local_addr.rsplit(":", 1)
                if len(addr_parts) != 2:
                    continue
                addr = addr_parts[0]
                try:
                    port_num = int(addr_parts[1])
                except ValueError:
                    continue
            
            # Extract PID/program if available
            pid = None
            program = None
            pid_match = re.search(r'pid=(\d+)', line)
            prog_match = re.search(r'"([^"]+)"', line)
            if pid_match:
                pid = int(pid_match.group(1))
            if prog_match:
                program = prog_match.group(1)
            
            protocol = parts[0].lower()
            if protocol in ("tcp", "tcp6"):
                protocol = "tcp"
            elif protocol in ("udp", "udp6"):
                protocol = "udp"
            
            ports.append(ListeningPort(
                protocol=protocol,
                address=addr,
                port=port_num,
                pid=pid,
                program=program
            ))
        
        return ports
    
    def _extract_proxy_targets(self, context: CheckContext) -> list[ProxyTarget]:
        """Extract all proxy_pass and fastcgi_pass targets from Nginx config."""
        targets: list[ProxyTarget] = []
        
        if not context.model.nginx:
            return targets
        
        # Build upstream lookup
        upstream_map: dict[str, list[str]] = {}
        for upstream in context.model.nginx.upstreams:
            upstream_map[upstream.name] = upstream.servers
        
        # Extract from all locations
        for server in context.model.nginx.servers:
            for location in server.locations:
                # Check proxy_pass
                if location.proxy_pass:
                    target = self._parse_proxy_target(
                        location.proxy_pass,
                        upstream_map,
                        location.source_file,
                        location.line_number,
                        location.path
                    )
                    if target:
                        targets.append(target)
                
                # Check fastcgi_pass
                if location.fastcgi_pass:
                    target = self._parse_fastcgi_target(
                        location.fastcgi_pass,
                        location.source_file,
                        location.line_number,
                        location.path
                    )
                    if target:
                        targets.append(target)
        
        return targets
    
    def _parse_proxy_target(
        self, 
        proxy_pass: str, 
        upstream_map: dict[str, list[str]],
        source_file: str,
        line_number: int,
        location_path: str
    ) -> ProxyTarget | None:
        """Parse a proxy_pass directive."""
        # Unix socket: http://unix:/path/to/socket.sock
        unix_match = re.match(r'https?://unix:([^:]+)', proxy_pass)
        if unix_match:
            return ProxyTarget(
                target_type="unix",
                socket_path=unix_match.group(1).rstrip(":"),
                source_file=source_file,
                line_number=line_number,
                location_path=location_path
            )
        
        # Direct IP:port: http://127.0.0.1:8080
        ip_match = re.match(r'https?://([^:/]+):(\d+)', proxy_pass)
        if ip_match:
            return ProxyTarget(
                target_type="tcp",
                host=ip_match.group(1),
                port=int(ip_match.group(2)),
                source_file=source_file,
                line_number=line_number,
                location_path=location_path
            )
        
        # Upstream name: http://upstream_name
        upstream_match = re.match(r'https?://([a-zA-Z_][a-zA-Z0-9_]*)', proxy_pass)
        if upstream_match:
            upstream_name = upstream_match.group(1)
            if upstream_name in upstream_map:
                return ProxyTarget(
                    target_type="upstream",
                    upstream_name=upstream_name,
                    source_file=source_file,
                    line_number=line_number,
                    location_path=location_path
                )
        
        return None
    
    def _parse_fastcgi_target(
        self,
        fastcgi_pass: str,
        source_file: str,
        line_number: int,
        location_path: str
    ) -> ProxyTarget | None:
        """Parse a fastcgi_pass directive."""
        # Unix socket: unix:/run/php/php8.3-fpm.sock
        if fastcgi_pass.startswith("unix:"):
            return ProxyTarget(
                target_type="unix",
                socket_path=fastcgi_pass[5:],
                source_file=source_file,
                line_number=line_number,
                location_path=location_path
            )
        
        # TCP: 127.0.0.1:9000
        tcp_match = re.match(r'([^:]+):(\d+)', fastcgi_pass)
        if tcp_match:
            return ProxyTarget(
                target_type="tcp",
                host=tcp_match.group(1),
                port=int(tcp_match.group(2)),
                source_file=source_file,
                line_number=line_number,
                location_path=location_path
            )
        
        return None
    
    def _check_dead_proxy_targets(
        self,
        targets: list[ProxyTarget],
        listening: list[ListeningPort],
        context: CheckContext
    ) -> list[Finding]:
        """PORT-1: Proxy target has no listening process."""
        findings = []
        
        # Build set of listening ports
        listening_set = {(p.port, p.address) for p in listening}
        listening_ports_only = {p.port for p in listening}
        
        for target in targets:
            if target.target_type == "tcp" and target.port:
                # Check if port is listening
                port_alive = (
                    target.port in listening_ports_only or
                    (target.port, target.host) in listening_set or
                    (target.port, "0.0.0.0") in listening_set or
                    (target.port, "*") in listening_set or
                    (target.port, "::") in listening_set
                )
                
                if not port_alive:
                    findings.append(Finding(
                        id="PORT-1",
                        severity=Severity.CRITICAL,
                        confidence=0.90,
                        condition=f"Proxy target port {target.port} has no listener",
                        cause=(
                            f"Nginx proxies to {target.host}:{target.port} but no process "
                            "is listening on that port. Requests will fail with 502."
                        ),
                        evidence=[Evidence(
                            source_file=target.source_file,
                            line_number=target.line_number,
                            excerpt=f"proxy_pass http://{target.host}:{target.port}",
                            command="ss -tulpn",
                        )],
                        treatment=(
                            f"Start the backend service that should listen on port {target.port}:\n"
                            f"    systemctl status <service-name>\n"
                            f"    systemctl start <service-name>"
                        ),
                        impact=[
                            "All requests to this location will fail",
                            "Users will see 502 Bad Gateway errors",
                        ],
                    ))
            
            elif target.target_type == "unix" and target.socket_path:
                # Check if socket exists
                if context.ssh:
                    result = context.ssh.run(
                        f"test -S {target.socket_path} && echo yes || echo no"
                    )
                    socket_exists = result.stdout.strip() == "yes"
                    
                    if not socket_exists:
                        findings.append(Finding(
                            id="PORT-1",
                            severity=Severity.CRITICAL,
                            confidence=0.95,
                            condition=f"Unix socket does not exist",
                            cause=(
                                f"Nginx proxies to socket {target.socket_path} but "
                                "the socket file does not exist."
                            ),
                            evidence=[Evidence(
                                source_file=target.source_file,
                                line_number=target.line_number,
                                excerpt=f"unix:{target.socket_path}",
                                command=f"test -S {target.socket_path}",
                            )],
                            treatment=(
                                "Start the service that creates this socket:\n"
                                f"    systemctl status php*-fpm\n"
                                f"    systemctl start php*-fpm"
                            ),
                            impact=[
                                "All requests to this location will fail",
                                "PHP/FastCGI processing will not work",
                            ],
                        ))
        
        return findings
    
    def _check_orphan_ports(
        self,
        listening: list[ListeningPort],
        targets: list[ProxyTarget],
        context: CheckContext
    ) -> list[Finding]:
        """PORT-2: Listening port not referenced by Nginx (info only)."""
        findings = []
        
        # Ports that should not be flagged
        common_ports = {22, 25, 53, 80, 443, 3306, 5432, 6379, 11211, 27017}
        
        # Build set of proxied ports
        proxied_ports = set()
        for target in targets:
            if target.port:
                proxied_ports.add(target.port)
        
        # Also add Nginx listen ports  
        if context.model.nginx:
            for server in context.model.nginx.servers:
                for listen_str in server.listen:
                    # extract port from "80 default_server" or "443 ssl"
                    match = re.search(r'(\d+)', listen_str)
                    if match:
                        proxied_ports.add(int(match.group(1)))
        
        # Find orphan ports
        orphan_ports = []
        for port in listening:
            if self._is_loopback_address(port.address):
                continue
            if port.port not in proxied_ports and port.port not in common_ports:
                # Skip loopback-only common services
                if port.address == "127.0.0.1" and port.port < 1024:
                    continue
                orphan_ports.append(port)
        
        if orphan_ports:
            # Group into single finding
            evidence_list = []
            for p in orphan_ports[:5]:  # Limit evidence
                prog = p.program or "unknown"
                evidence_list.append(Evidence(
                    source_file="",
                    line_number=0,
                    excerpt=f"{p.protocol.upper()} {p.address}:{p.port} ({prog})",
                    command="ss -tulpn",
                ))
            
            findings.append(Finding(
                id="PORT-2",
                severity=Severity.INFO,
                confidence=0.60,
                condition=f"{len(orphan_ports)} listening port(s) not served by Nginx",
                cause=(
                    "These ports are listening but not referenced in any Nginx "
                    "proxy_pass directive. They may be internal services or unused."
                ),
                evidence=evidence_list,
                treatment=(
                    "Review if these services should be:\n"
                    "    1. Proxied through Nginx for public access\n"
                    "    2. Left as internal services\n"
                    "    3. Disabled if unused"
                ),
                impact=[
                    "No immediate issue",
                    "May indicate unused services consuming resources",
                ],
            ))
        
        return findings

    @staticmethod
    def _is_loopback_address(address: str) -> bool:
        addr = (address or "").strip().lower().strip("[]")
        return addr == "localhost" or addr == "::1" or addr.startswith("127.")
