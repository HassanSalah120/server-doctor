"""Read-only backup/readiness scanner."""

from __future__ import annotations

from server_doctor.model.server import BackupReadinessModel


class BackupReadinessScanner:
    def __init__(self, ssh) -> None:
        self.ssh = ssh

    def _run_readonly(self, command: str, *, timeout: float):
        try:
            return self.ssh.run(command, use_sudo=False, timeout=timeout)
        except TypeError:
            return self.ssh.run(command)

    def scan(self) -> BackupReadinessModel:
        tools = self._run_readonly(
            "timeout 5s sh -lc 'command -v restic borgbackup duplicity rsnapshot 2>/dev/null || true'",
            timeout=7,
        )
        return BackupReadinessModel(
            enabled=True,
            tools_detected=[line.strip() for line in tools.stdout.splitlines() if line.strip()],
        )
