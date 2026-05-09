"""Read-only Node/PM2/systemd/Vite runtime scanner."""

from __future__ import annotations

import re

from server_doctor.model.server import NetworkEndpoint, NodeRuntimeModel, NodeRuntimeProcess


class NodeRuntimeScanner:
    def __init__(self, ssh) -> None:
        self.ssh = ssh

    def _run_readonly(self, command: str, *, timeout: float) -> str:
        wrapped = f"timeout {max(1, int(timeout) - 2)}s sh -lc {sh_quote(command)}"
        try:
            return self.ssh.run(wrapped, use_sudo=False, timeout=timeout).stdout
        except TypeError:
            return self.ssh.run(command).stdout

    def scan(self) -> NodeRuntimeModel:
        model = NodeRuntimeModel(enabled=True)
        ps_command = (
            "ps -eo pid,user,comm,args | grep -E 'node|npm|pm2' "
            "| grep -v grep || true"
        )
        ps = self._run_readonly(ps_command, timeout=10)
        for line in ps.splitlines():
            parts = line.split(maxsplit=3)
            if len(parts) < 4:
                continue
            pid, user, _comm, args = parts
            model.processes.append(
                NodeRuntimeProcess(
                    name=args[:80],
                    pid=_int(pid),
                    manager="pm2" if "pm2" in args else "systemd" if "node" in args else "unknown",
                    status="running",
                    user=user,
                )
            )
        ss = self._run_readonly("ss -ltnp 2>/dev/null || true", timeout=10)
        model.listeners = _parse_listeners(ss)
        return model


def sh_quote(value: str) -> str:
    return "'" + value.replace("'", "'\"'\"'") + "'"


def _parse_listeners(text: str) -> list[NetworkEndpoint]:
    endpoints: list[NetworkEndpoint] = []
    for line in text.splitlines():
        match = re.search(r"(?P<addr>[\d\.:]+):(?P<port>\d+)\s", line)
        if not match:
            continue
        endpoints.append(
            NetworkEndpoint(
                protocol="tcp",
                address=match.group("addr").rsplit(":", 1)[0],
                port=int(match.group("port")),
            )
        )
    return endpoints


def _int(value: str) -> int | None:
    try:
        return int(value)
    except ValueError:
        return None
