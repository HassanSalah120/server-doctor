"""Read-only Redis deep scanner."""

from __future__ import annotations

from server_doctor.model.server import RedisDeepModel, RedisInstance


class RedisDeepScanner:
    def __init__(self, ssh) -> None:
        self.ssh = ssh

    def _run_readonly(self, command: str, *, timeout: float) -> str:
        try:
            return self.ssh.run(command, use_sudo=False, timeout=timeout).stdout
        except TypeError:
            return self.ssh.run(command).stdout

    def scan(self) -> RedisDeepModel:
        state = self._run_readonly(
            "timeout 5s systemctl is-active redis redis-server 2>/dev/null || true",
            timeout=7,
        )
        return RedisDeepModel(
            enabled=True,
            service_state=_first_line(state),
            instances=[],
            scanner_available=True,
        )


def from_instances(instances: list[RedisInstance]) -> RedisDeepModel:
    return RedisDeepModel(enabled=True, instances=instances, scanner_available=True)


def _first_line(text: str) -> str | None:
    for line in text.splitlines():
        if line.strip():
            return line.strip()
    return None
