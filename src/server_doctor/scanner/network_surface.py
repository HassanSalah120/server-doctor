"""Network Surface Scanner - Collects live listening network endpoints."""

from __future__ import annotations

import re

from server_doctor.connector.ssh import SSHConnector
from server_doctor.model.server import NetworkEndpoint, NetworkSurfaceModel


SERVICE_PORT_MAP: dict[int, str] = {
    21: "ftp",
    22: "ssh",
    23: "telnet",
    25: "smtp",
    53: "dns",
    80: "http",
    110: "pop3",
    143: "imap",
    443: "https",
    465: "smtps",
    587: "submission",
    6379: "redis",
    3306: "mysql",
    5432: "postgresql",
    27017: "mongodb",
    11211: "memcached",
    9200: "elasticsearch",
    2375: "docker-api",
    3389: "rdp",
}


class NetworkSurfaceScanner:
    """Scanner for live network exposure on the host."""

    def __init__(self, ssh: SSHConnector) -> None:
        self.ssh = ssh

    def scan(self) -> NetworkSurfaceModel:
        """Collect listening TCP/UDP endpoints."""
        result = self.ssh.run("ss -H -lntuap 2>/dev/null || netstat -tulpn 2>/dev/null")
        if not result.success and not result.stdout.strip():
            return NetworkSurfaceModel()

        endpoints: dict[tuple[str, str, int, int | None], NetworkEndpoint] = {}
        for line in result.stdout.splitlines():
            ep = self._parse_line(line)
            if not ep:
                continue
            key = (ep.protocol, ep.address, ep.port, ep.pid)
            if key not in endpoints:
                endpoints[key] = ep

        ordered = sorted(
            endpoints.values(),
            key=lambda e: (0 if e.public_exposed else 1, e.port, e.protocol, e.address),
        )
        return NetworkSurfaceModel(endpoints=ordered)

    def _parse_line(self, line: str) -> NetworkEndpoint | None:
        clean = line.strip()
        if not clean:
            return None

        parts = clean.split()
        if not parts:
            return None

        proto_raw = parts[0].lower()
        if not proto_raw.startswith(("tcp", "udp")):
            return None
        protocol = "tcp" if proto_raw.startswith("tcp") else "udp"

        local_token = self._find_local_token(parts)
        if not local_token:
            return None

        address, port = self._split_address_port(local_token)
        if port is None:
            return None

        pid = None
        pid_match = re.search(r"pid=(\d+)", clean)
        if pid_match:
            pid = int(pid_match.group(1))

        program = None
        prog_match = re.search(r'"([^"]+)"', clean)
        if prog_match:
            program = prog_match.group(1)

        service = self._guess_service(program, port)
        public_exposed = self._is_public_exposed(address)

        return NetworkEndpoint(
            protocol=protocol,
            address=address,
            port=port,
            pid=pid,
            program=program,
            service=service,
            public_exposed=public_exposed,
        )

    def _find_local_token(self, parts: list[str]) -> str | None:
        # Prefer tokens that look like address:port but skip remote wildcard/peer tokens.
        for token in parts:
            if token in {"*", "*:*"}:
                continue
            if re.match(r"^\[[^\]]+\]:\d+$", token):
                return token
            if re.match(r"^[^:\s]+:\d+$", token):
                return token
        return None

    def _split_address_port(self, token: str) -> tuple[str, int | None]:
        if token.startswith("[") and "]:" in token:
            host_part, port_part = token.rsplit("]:", 1)
            host = host_part.lstrip("[")
            return host, int(port_part) if port_part.isdigit() else None

        if ":" not in token:
            return token, None

        host, port_part = token.rsplit(":", 1)
        if not port_part.isdigit():
            return host, None
        return host, int(port_part)

    def _is_public_exposed(self, address: str) -> bool:
        return address in {"0.0.0.0", "::", "*", "[::]"}

    def _guess_service(self, program: str | None, port: int) -> str | None:
        if program:
            lowered = program.lower()
            if "nginx" in lowered:
                return "nginx"
            if "sshd" in lowered:
                return "ssh"
            if "redis" in lowered:
                return "redis"
            if "mysqld" in lowered or "mariadb" in lowered:
                return "mysql"
            if "postgres" in lowered:
                return "postgresql"
            if "docker" in lowered:
                return "docker"
            if "node" in lowered:
                return "node"
            return lowered
        return SERVICE_PORT_MAP.get(port)
