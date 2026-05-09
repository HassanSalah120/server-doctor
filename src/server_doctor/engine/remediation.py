"""Remediation Engine - Generates environment-specific commands based on topology.

Translates generic actions (reload, test, restart) into specific commands
for Docker, Systemd, or native environments.
"""

from typing import Any
from server_doctor.engine.remediation_classifier import classify_impact
from server_doctor.model.server import ServerModel


class RemediationGenerator:
    """Generates commands based on ServerModel topology."""

    def __init__(self, topology: ServerModel) -> None:
        self.topology = topology
        self.os_type = topology.hostname.lower() # Fallback
        # Check for OS in topology if available
        # The prompt mentioned topology.os=ubuntu or topology.mode=docker
        self.is_docker = self._is_docker_environment()
        self.is_systemd = self._has_systemd()

    def classify_downtime(self, rule_id: str, title: str) -> str:
        """Delegate to the shared classifier."""
        return classify_impact(rule_id, title)

    def _is_docker_environment(self) -> bool:
        """Check if target Nginx is likely containerized."""
        if hasattr(self.topology, "services") and self.topology.services.docker_containers:
            # Check if an nginx container exists
            for c in self.topology.services.docker_containers:
                if "nginx" in c.image.lower() or "nginx" in c.name.lower():
                    return True
        return False

    def _has_systemd(self) -> bool:
        """Check if target has systemd and an nginx service."""
        if hasattr(self.topology, "runtime") and self.topology.runtime.systemd_services:
            for s in self.topology.runtime.systemd_services:
                if s.name == "nginx.service" or s.name == "nginx":
                    return True
        return False

    def get_reload_command(self) -> str:
        """Command to reload Nginx config."""
        if self.is_docker:
            # Find the nginx container name
            name = self._get_nginx_container_name() or "nginx"
            return f"docker exec {name} nginx -s reload"
        if self.is_systemd:
            return "systemctl reload nginx"
        return "nginx -s reload"

    def get_test_command(self) -> str:
        """Command to test Nginx config."""
        if self.is_docker:
            name = self._get_nginx_container_name() or "nginx"
            return f"docker exec {name} nginx -t"
        return "nginx -t"

    def get_install_command(self, package: str) -> str:
        """Command to install a package (apt fallback)."""
        # In a real version, we'd check topology for os_release
        return f"apt-get install -y {package}"

    def get_edit_path(self, original_path: str) -> str:
        """Return the path to be edited (maps Docker volumes if needed)."""
        # In this MVP, we assume the provided paths in ServerModel are target paths.
        return original_path

    def _get_nginx_container_name(self) -> str | None:
        if hasattr(self.topology, "services") and self.topology.services.docker_containers:
            for c in self.topology.services.docker_containers:
                if "nginx" in c.image.lower() or "nginx" in c.name.lower():
                    return c.name
        return None

    def wrap_fix(self, fix_step: str) -> str:
        """Inject topology-aware commands into a fix description."""
        if "reload nginx" in fix_step.lower():
            return fix_step.replace("reload Nginx", f"`{self.get_reload_command()}`")
        if "nginx -t" in fix_step.lower():
            return fix_step.replace("nginx -t", f"`{self.get_test_command()}`")
        return fix_step
