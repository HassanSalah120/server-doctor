"""Kernel Limits Scanner - Captures host limits/sysctl tuning signals."""

from __future__ import annotations

import os
import re

from server_doctor.connector.ssh import CommandResult, SSHConnector
from server_doctor.model.server import KernelLimitsModel


class KernelLimitsScanner:
    """Collect ulimit + sysctl + nginx worker limit posture."""

    _WORKER_CONN_RE = re.compile(r"^\s*worker_connections\s+(\d+)\s*;", re.MULTILINE)
    _WORKER_PROC_RE = re.compile(r"^\s*worker_processes\s+([^;]+)\s*;", re.MULTILINE)

    def __init__(self, ssh: SSHConnector) -> None:
        self.ssh = ssh
        self._nginx_dump_timeout = float(self._env_int("server_doctor_KERNEL_NGINX_DUMP_TIMEOUT", 10, min_value=3, max_value=30))

    def scan(self) -> KernelLimitsModel:
        model = KernelLimitsModel()
        self._collect_ulimits(model)
        self._collect_sysctl(model)
        self._collect_nginx_worker_limits(model)
        return model

    def _env_int(self, name: str, default: int, min_value: int = 0, max_value: int = 1_000_000) -> int:
        raw = os.getenv(name, str(default)).strip()
        try:
            value = int(raw)
        except ValueError:
            value = default
        return max(min_value, min(max_value, value))

    def _classify_result(
        self,
        result: CommandResult,
        *,
        empty_status: str = "not_observed",
        missing_status: str = "unavailable",
    ) -> tuple[str, str]:
        if result.success:
            out = (result.stdout or "").strip()
            return ("collected", "") if out else (empty_status, "")

        stderr = (result.stderr or "").strip().lower()
        if any(token in stderr for token in ("permission denied", "operation not permitted", "not in the sudoers", "sudo authentication failed")):
            return ("insufficient_permissions", stderr[:220])
        if any(token in stderr for token in ("command not found", "not found", "no such file", "no such command")):
            return (missing_status, stderr[:220])
        if any(
            token in stderr
            for token in (
                "ssh execution error",
                "channelexception",
                "connect failed",
                "no existing session",
                "socket is closed",
                "connection reset",
            )
        ):
            return ("not_accessible", stderr[:220])
        if "timed out" in stderr or "timeout" in stderr:
            return ("timeout", stderr[:220])
        return ("error", stderr[:220] or f"exit_code={result.exit_code}")

    def _run_stdout(
        self,
        command: str,
        *,
        timeout: float = 6,
        use_sudo: bool = True,
        empty_status: str = "not_observed",
        missing_status: str = "unavailable",
    ) -> tuple[str, str, str]:
        result = self.ssh.run(command, timeout=timeout, use_sudo=use_sudo)
        status, note = self._classify_result(
            result,
            empty_status=empty_status,
            missing_status=missing_status,
        )
        if not result.success:
            return ("", status, note)
        return ((result.stdout or "").strip(), status, note)

    def _record(self, model: KernelLimitsModel, key: str, status: str, note: str = "") -> None:
        model.collection_status[key] = status
        if note:
            model.collection_notes[key] = note[:220]

    def _to_int(self, value: str) -> int | None:
        clean = value.strip()
        if clean.isdigit():
            return int(clean)
        return None

    def _collect_ulimits(self, model: KernelLimitsModel) -> None:
        output, status, note = self._run_stdout(
            "sh -lc 'ulimit -Sn; ulimit -Hn' 2>/dev/null",
            timeout=5,
            use_sudo=False,
            empty_status="not_observed",
        )
        self._record(model, "kernel.ulimit_nofile", status, note)
        if not output:
            return
        lines = [line.strip() for line in output.splitlines() if line.strip()]
        if len(lines) >= 1:
            model.nofile_soft = self._to_int(lines[0])
        if len(lines) >= 2:
            model.nofile_hard = self._to_int(lines[1])

    def _collect_sysctl(self, model: KernelLimitsModel) -> None:
        command = (
            "sh -lc '"
            "echo fs_file_max=$(cat /proc/sys/fs/file-max 2>/dev/null); "
            "echo somaxconn=$(cat /proc/sys/net/core/somaxconn 2>/dev/null); "
            "echo tcp_max_syn_backlog=$(cat /proc/sys/net/ipv4/tcp_max_syn_backlog 2>/dev/null); "
            "echo tcp_fin_timeout=$(cat /proc/sys/net/ipv4/tcp_fin_timeout 2>/dev/null); "
            "echo netdev_max_backlog=$(cat /proc/sys/net/core/netdev_max_backlog 2>/dev/null); "
            "echo ip_local_port_range=$(cat /proc/sys/net/ipv4/ip_local_port_range 2>/dev/null)"
            "'"
        )
        output, status, note = self._run_stdout(
            command,
            timeout=4,
            use_sudo=False,
            empty_status="not_observed",
        )
        probe_keys = {
            "fs_file_max": "kernel.fs_file_max",
            "somaxconn": "kernel.somaxconn",
            "tcp_max_syn_backlog": "kernel.tcp_max_syn_backlog",
            "tcp_fin_timeout": "kernel.tcp_fin_timeout",
            "netdev_max_backlog": "kernel.netdev_max_backlog",
            "ip_local_port_range": "kernel.ip_local_port_range",
        }

        if status != "collected":
            for key in probe_keys.values():
                self._record(model, key, status, note)
            return

        parsed: dict[str, str] = {}
        for raw in output.splitlines():
            line = raw.strip()
            if "=" not in line:
                continue
            key, value = line.split("=", 1)
            parsed[key.strip()] = value.strip()

        def _record_value(model_key: str, parsed_key: str) -> str:
            value = parsed.get(parsed_key, "")
            if value:
                self._record(model, model_key, "collected")
            else:
                self._record(model, model_key, "not_observed")
            return value

        model.fs_file_max = self._to_int(_record_value(probe_keys["fs_file_max"], "fs_file_max"))
        model.somaxconn = self._to_int(_record_value(probe_keys["somaxconn"], "somaxconn"))
        model.tcp_max_syn_backlog = self._to_int(_record_value(probe_keys["tcp_max_syn_backlog"], "tcp_max_syn_backlog"))
        model.tcp_fin_timeout = self._to_int(_record_value(probe_keys["tcp_fin_timeout"], "tcp_fin_timeout"))
        model.netdev_max_backlog = self._to_int(_record_value(probe_keys["netdev_max_backlog"], "netdev_max_backlog"))

        port_range = _record_value(probe_keys["ip_local_port_range"], "ip_local_port_range")
        if port_range:
            parts = port_range.split()
            if len(parts) >= 2 and parts[0].isdigit() and parts[1].isdigit():
                model.ip_local_port_range_start = int(parts[0])
                model.ip_local_port_range_end = int(parts[1])

    def _collect_nginx_worker_limits(self, model: KernelLimitsModel) -> None:
        dump, status, note = self._run_stdout(
            "nginx -T",
            timeout=self._nginx_dump_timeout,
            empty_status="not_observed",
            missing_status="not_supported",
        )
        self._record(model, "kernel.nginx_dump", status, note)
        if not dump:
            return

        match = self._WORKER_CONN_RE.search(dump)
        if match:
            try:
                model.nginx_worker_connections = int(match.group(1))
            except ValueError:
                pass

        proc_match = self._WORKER_PROC_RE.search(dump)
        if not proc_match:
            return

        token = proc_match.group(1).strip().lower()
        if token.isdigit():
            model.nginx_worker_processes = int(token)
            return
        if token == "auto":
            nproc, nproc_status, nproc_note = self._run_stdout(
                "nproc 2>/dev/null",
                timeout=3,
                use_sudo=False,
                empty_status="not_observed",
            )
            self._record(model, "kernel.nproc", nproc_status, nproc_note)
            if nproc.isdigit():
                model.nginx_worker_processes = int(nproc)
