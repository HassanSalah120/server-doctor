"""Docker Scanner - Collects container information via Engine API or CLI.

This scanner prioritizes direct communication with the Docker Engine API over
the unix socket for precision, falling back to the CLI if needed.
"""

import json
from dataclasses import dataclass, field

from server_doctor.connector.ssh import SSHConnector
from server_doctor.model.server import (
    CapabilityLevel,
    CapabilityReason,
    DockerContainer,
    DockerPort,
    ServiceState,
    ServiceStatus,
)


@dataclass
class DockerScanResult:
    """Raw Docker scan results."""

    status: ServiceStatus
    containers: list[DockerContainer] = field(default_factory=list)


class DockerScanner:
    """Scanner for Docker host and containers.

    Collects:
    - Docker Engine status and version
    - Running and stopped containers
    - Restart counts and port mappings
    - Volume mounts (for app detection)
    """

    SOCKET_PATH = "/var/run/docker.sock"

    def __init__(self, ssh: SSHConnector) -> None:
        self.ssh = ssh

    def scan(self) -> DockerScanResult:
        """Perform full Docker scan.

        Returns:
            DockerScanResult with all collected data.
        """
        # 1. Detect if Docker is even installed/present
        if not self._is_docker_present():
            return DockerScanResult(
                status=ServiceStatus(
                    capability=CapabilityLevel.NONE,
                    state=ServiceState.NOT_INSTALLED,
                    reason=CapabilityReason.BINARY_MISSING,
                )
            )

        # 2. Try Engine API over Socket (FULL)
        api_result = self._scan_via_api()
        if api_result:
            return api_result

        # 3. Fallback to CLI (LIMITED)
        cli_result = self._scan_via_cli()
        if cli_result:
            return cli_result

        # 4. If all failed but binary exists, it's likely stopped or totally inaccessible
        return DockerScanResult(
            status=ServiceStatus(
                capability=CapabilityLevel.NONE,
                state=ServiceState.STOPPED,
                reason=CapabilityReason.DAEMON_UNREACHABLE,
            )
        )

    def _is_docker_present(self) -> bool:
        """Check if docker binary or socket exists."""
        # Check binary
        if self.ssh.run("which docker", timeout=4).success:
            return True
        # Check socket
        if self.ssh.file_exists(self.SOCKET_PATH):
            return True
        return False

    def _scan_via_api(self) -> DockerScanResult | None:
        """Attempt to scan via Docker Engine API over unix socket."""
        # Check socket permissions first
        stat_result = self.ssh.run(f"stat -c '%a' {self.SOCKET_PATH}", timeout=4)
        if not stat_result.success:
            return None  # Socket doesn't exist or stat failed

        # Try curl with --unix-socket
        test_cmd = f"curl --unix-socket {self.SOCKET_PATH} http://localhost/_ping"
        if not self.ssh.run(test_cmd, timeout=4).success:
            # Maybe curl doesn't support unix sockets or permission denied
            test_nc = f"echo -e 'GET /_ping HTTP/1.0\\r\\n' | nc -U {self.SOCKET_PATH}"
            if not self.ssh.run(test_nc, timeout=4).success:
                return None

        # If we got here, we have socket access!
        # Get Version
        version_cmd = f"curl --unix-socket {self.SOCKET_PATH} http://localhost/version"
        v_data = self._get_json_via_socket(version_cmd)
        version = v_data.get("Version") if v_data else None

        # Get Containers
        containers_cmd = f"curl --unix-socket {self.SOCKET_PATH} http://localhost/containers/json?all=1"
        c_list = self._get_json_via_socket(containers_cmd)
        
        containers: list[DockerContainer] = []
        if isinstance(c_list, list):
            for c in c_list:
                # We need more detail (restarts, mounts) from inspect
                inspect_cmd = f"curl --unix-socket {self.SOCKET_PATH} http://localhost/containers/{c['Id']}/json"
                detail = self._get_json_via_socket(inspect_cmd)
                if detail:
                    containers.append(self._parse_container_detail(detail))

        return DockerScanResult(
            status=ServiceStatus(
                capability=CapabilityLevel.FULL,
                state=ServiceState.RUNNING,
                version=version,
            ),
            containers=containers,
        )

    def _scan_via_cli(self) -> DockerScanResult | None:
        """Fallback to scanning via Docker CLI."""
        # check if docker ps works
        ps_result = self.ssh.run("docker ps --format '{{json .}}' --all", timeout=10)
        if not ps_result.success:
            # If it failed due to permission, track that
            if "permission denied" in ps_result.stderr.lower():
                return DockerScanResult(
                    status=ServiceStatus(
                        capability=CapabilityLevel.NONE,
                        state=ServiceState.RUNNING,
                        reason=CapabilityReason.PERMISSION_DENIED,
                    )
                )
            return None

        containers: list[DockerContainer] = []
        lines = ps_result.stdout.strip().split("\n")
        container_ids = []
        for line in lines:
            if not line.strip():
                continue
            try:
                c_data = json.loads(line)
                container_ids.append(c_data['ID'])
            except (json.JSONDecodeError, KeyError):
                continue
        
        if container_ids:
            # Batch inspect
            inspect_cmd = f"docker inspect {' '.join(container_ids)}"
            inspect_result = self.ssh.run(inspect_cmd, timeout=15)
            if inspect_result.success:
                try:
                    details = json.loads(inspect_result.stdout)
                    for detail in details:
                        containers.append(self._parse_container_detail(detail))
                except json.JSONDecodeError:
                    pass

        # Get version
        v_result = self.ssh.run("docker version --format '{{.Server.Version}}'", timeout=4)
        version = v_result.stdout.strip() if v_result.success else None

        return DockerScanResult(
            status=ServiceStatus(
                capability=CapabilityLevel.LIMITED,
                state=ServiceState.RUNNING,
                version=version,
                reason=CapabilityReason.SOCKET_MISSING, # Implicit if we are here and ps worked but socket failed earlier
            ),
            containers=containers,
        )

    def _get_json_via_socket(self, cmd: str) -> dict | list | None:
        """Helper to run a curl command and parse JSON."""
        result = self.ssh.run(cmd, timeout=5)
        if result.success and result.stdout.strip():
            try:
                return json.loads(result.stdout)
            except json.JSONDecodeError:
                return None
        return None

    def _parse_container_detail(self, detail: dict) -> DockerContainer:
        """Convert Docker Engine API/Inspect JSON into DockerContainer model."""
        ports: list[DockerPort] = []
        network_settings = detail.get("NetworkSettings", {})
        port_bindings = network_settings.get("Ports", {}) or {}

        for container_p_proto, bindings in port_bindings.items():
            # container_p_proto is e.g. "80/tcp"
            try:
                c_port_str, proto = container_p_proto.split("/")
                c_port = int(c_port_str)
                
                if bindings:
                    for b in bindings:
                        ports.append(DockerPort(
                            container_port=c_port,
                            host_ip=b.get("HostIp", "0.0.0.0"),
                            host_port=int(b["HostPort"]) if b.get("HostPort") else None,
                            proto=proto
                        ))
                else:
                    # Not published, just exposed internal
                    ports.append(DockerPort(container_port=c_port, proto=proto))
            except (ValueError, KeyError):
                continue

        mounts: list[dict[str, str]] = []
        for m in detail.get("Mounts", []):
            mounts.append({
                "source": m.get("Source", ""),
                "destination": m.get("Destination", ""),
                "type": m.get("Type", "volume"),
            })

        return DockerContainer(
            id=detail.get("Id"),
            name=detail.get("Name", "").lstrip("/"),
            image=detail.get("Config", {}).get("Image", ""),
            status=detail.get("State", {}).get("Status", "unknown"),
            main_pid=detail.get("State", {}).get("Pid"),
            restart_count=detail.get("RestartCount", 0),
            ports=ports,
            mounts=mounts,
        )
