"""Read-only MySQL/MariaDB deep scanner."""

from __future__ import annotations

import re

from server_doctor.model.server import MySQLDeepModel


class MySQLDeepScanner:
    def __init__(self, ssh) -> None:
        self.ssh = ssh

    def _run_readonly(self, command: str, *, timeout: float) -> str:
        try:
            return self.ssh.run(command, use_sudo=False, timeout=timeout).stdout
        except TypeError:
            return self.ssh.run(command).stdout

    def scan(self) -> MySQLDeepModel:
        state = self._run_readonly(
            "timeout 5s systemctl is-active mysql mariadb 2>/dev/null || true",
            timeout=7,
        )
        config_command = (
            "timeout 8s grep -R '^bind-address' /etc/mysql /etc/my.cnf 2>/dev/null || true"
        )
        config = self._run_readonly(config_command, timeout=10)
        return MySQLDeepModel(
            enabled=True,
            installed=bool(state.strip() or config.strip()),
            service_state=_first_state(state),
            bind_addresses=_bind_addresses(config),
        )


def _first_state(text: str) -> str | None:
    for line in text.splitlines():
        if line.strip():
            return line.strip()
    return None


def _bind_addresses(text: str) -> list[str]:
    values: list[str] = []
    for match in re.finditer(r"bind-address\s*=\s*([^\s#]+)", text, re.I):
        values.append(match.group(1))
    return values
