"""Resources Scanner - Captures runtime pressure and process hotspots."""

from __future__ import annotations

import os
import re

from server_doctor.connector.ssh import CommandResult, SSHConnector
from server_doctor.model.server import ResourcesModel


class ResourcesScanner:
    """Collect pressure-oriented host resource metrics."""

    _PSI_RE = re.compile(r"avg10=([0-9]+(?:\.[0-9]+)?)")

    def __init__(self, ssh: SSHConnector) -> None:
        self.ssh = ssh
        self._top_process_rows = self._env_int("server_doctor_RESOURCES_TOP_PROCESS_ROWS", 8, min_value=4, max_value=25)

    def scan(self) -> ResourcesModel:
        model = ResourcesModel()
        self._collect_cpu_load(model)
        self._collect_memory_swap(model)
        self._collect_oom_events(model)
        self._collect_top_processes(model)
        self._collect_psi(model)
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
        timeout: float = 8,
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

    def _record(self, model: ResourcesModel, key: str, status: str, note: str = "") -> None:
        model.collection_status[key] = status
        if note:
            model.collection_notes[key] = note[:220]

    def _collect_cpu_load(self, model: ResourcesModel) -> None:
        nproc, status, note = self._run_stdout("nproc 2>/dev/null", timeout=4, use_sudo=False, empty_status="not_observed")
        self._record(model, "resources.nproc", status, note)
        if nproc.isdigit():
            model.cpu_cores = int(nproc)

        loadavg, status, note = self._run_stdout("cat /proc/loadavg 2>/dev/null", timeout=4, use_sudo=False, empty_status="not_observed")
        self._record(model, "resources.loadavg", status, note)
        parts = loadavg.split()
        if len(parts) >= 3:
            try:
                model.load_1 = float(parts[0])
                model.load_5 = float(parts[1])
                model.load_15 = float(parts[2])
            except ValueError:
                pass

    def _collect_memory_swap(self, model: ResourcesModel) -> None:
        meminfo, status, note = self._run_stdout("cat /proc/meminfo 2>/dev/null", timeout=4, use_sudo=False, empty_status="not_observed")
        self._record(model, "resources.meminfo", status, note)
        if not meminfo:
            return

        values: dict[str, int] = {}
        for raw in meminfo.splitlines():
            line = raw.strip()
            if ":" not in line:
                continue
            key, rest = line.split(":", 1)
            parts = rest.strip().split()
            if not parts or not parts[0].isdigit():
                continue
            values[key.strip()] = int(parts[0])

        if "MemTotal" in values:
            model.mem_total_mb = values["MemTotal"] // 1024
        if "MemAvailable" in values:
            model.mem_available_mb = values["MemAvailable"] // 1024
        if "SwapTotal" in values:
            model.swap_total_mb = values["SwapTotal"] // 1024
        if "SwapFree" in values:
            model.swap_free_mb = values["SwapFree"] // 1024

    def _collect_oom_events(self, model: ResourcesModel) -> None:
        _, check_status, check_note = self._run_stdout(
            "command -v journalctl 2>/dev/null",
            timeout=3,
            use_sudo=False,
            empty_status="not_supported",
            missing_status="not_supported",
        )
        if check_status != "collected":
            self._record(model, "resources.journal_oom", check_status, check_note or "journalctl binary not available")
        else:
            journal_oom, status, note = self._run_stdout(
                "journalctl -k --since '24 hours ago' --no-pager 2>/dev/null "
                "| grep -v 'COMMAND=' "
                "| grep -cE 'Out of memory:|Killed process|oom-kill:|Memory cgroup out of memory|invoked oom-killer'",
                timeout=8,
                empty_status="not_observed",
            )
            self._record(model, "resources.journal_oom", status, note)
            if journal_oom.isdigit():
                model.oom_events_24h = int(journal_oom)

            oom_raw, _, _ = self._run_stdout(
                "journalctl -k --since '24 hours ago' --no-pager 2>/dev/null "
                "| grep -v 'COMMAND=' "
                "| grep -E 'Out of memory:|Killed process|oom-kill:|Memory cgroup out of memory|invoked oom-killer' "
                "| tail -5",
                timeout=8,
                empty_status="not_observed",
            )
            if oom_raw:
                model.oom_samples = [l for l in oom_raw.splitlines() if l.strip()]
            return

        dmesg_oom, status, note = self._run_stdout(
            "dmesg 2>/dev/null | grep -v 'COMMAND=' "
            "| grep -cE 'Out of memory:|Killed process|oom-kill:|Memory cgroup out of memory|invoked oom-killer'",
            timeout=6,
            empty_status="not_observed",
        )
        self._record(model, "resources.dmesg_oom", status, note)
        if dmesg_oom.isdigit():
            model.oom_events_24h = int(dmesg_oom)

        dmesg_raw, _, _ = self._run_stdout(
            "dmesg 2>/dev/null | grep -v 'COMMAND=' "
            "| grep -E 'Out of memory:|Killed process|oom-kill:|Memory cgroup out of memory|invoked oom-killer' "
            "| tail -5",
            timeout=6,
            empty_status="not_observed",
        )
        if dmesg_raw:
            model.oom_samples = [l for l in dmesg_raw.splitlines() if l.strip()]

    def _collect_top_processes(self, model: ResourcesModel) -> None:
        top_cpu, status, note = self._run_stdout(
            f"ps -eo pid,comm,%cpu,%mem --sort=-%cpu 2>/dev/null | head -n {self._top_process_rows}",
            timeout=6,
            use_sudo=False,
            empty_status="not_observed",
        )
        self._record(model, "resources.ps_cpu", status, note)
        if top_cpu:
            lines = [line.strip() for line in top_cpu.splitlines() if line.strip()]
            model.top_cpu_processes = lines[1:7] if len(lines) > 1 else lines[:6]

        top_mem, status, note = self._run_stdout(
            f"ps -eo pid,comm,%cpu,%mem --sort=-%mem 2>/dev/null | head -n {self._top_process_rows}",
            timeout=6,
            use_sudo=False,
            empty_status="not_observed",
        )
        self._record(model, "resources.ps_mem", status, note)
        if top_mem:
            lines = [line.strip() for line in top_mem.splitlines() if line.strip()]
            model.top_mem_processes = lines[1:7] if len(lines) > 1 else lines[:6]

    def _collect_psi(self, model: ResourcesModel) -> None:
        model.psi_cpu_some_avg10 = self._psi_avg10(model, "/proc/pressure/cpu", "resources.psi_cpu")
        model.psi_memory_some_avg10 = self._psi_avg10(model, "/proc/pressure/memory", "resources.psi_memory")
        model.psi_io_some_avg10 = self._psi_avg10(model, "/proc/pressure/io", "resources.psi_io")

    def _psi_avg10(self, model: ResourcesModel, path: str, key: str) -> float | None:
        text, status, note = self._run_stdout(
            f"cat {path} 2>/dev/null",
            timeout=3,
            use_sudo=False,
            empty_status="not_supported",
            missing_status="not_supported",
        )
        self._record(model, key, status, note)
        if not text:
            return None
        for raw in text.splitlines():
            line = raw.strip()
            if not line.startswith("some"):
                continue
            match = self._PSI_RE.search(line)
            if not match:
                continue
            try:
                return float(match.group(1))
            except ValueError:
                return None
        return None
