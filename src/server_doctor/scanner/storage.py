"""Storage Scanner - Collects disk/inode/mount and IO-pressure signals."""

from __future__ import annotations

import os

from server_doctor.connector.ssh import CommandResult
from server_doctor.connector.ssh import SSHConnector
from server_doctor.model.server import StorageModel, StorageMountModel


class StorageScanner:
    """Collect storage health data for analyzer checks."""

    def __init__(self, ssh: SSHConnector) -> None:
        self.ssh = ssh
        self._dmesg_tail_lines = self._env_int("server_doctor_STORAGE_DMESG_TAIL_LINES", 20, min_value=5, max_value=200)

    def scan(self) -> StorageModel:
        model = StorageModel()
        self._collect_mount_usage(model)
        self._collect_read_only_mounts(model)
        self._collect_failed_mount_units(model)
        self._collect_iowait(model)
        self._collect_io_errors(model)
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

    def _record(self, model: StorageModel, key: str, status: str, note: str = "") -> None:
        model.collection_status[key] = status
        if note:
            model.collection_notes[key] = note[:220]

    def _collect_mount_usage(self, model: StorageModel) -> None:
        inode_pct_by_mount: dict[str, float] = {}
        inode_res, status, note = self._run_stdout("df -P -i 2>/dev/null", timeout=8, use_sudo=False, empty_status="not_observed")
        self._record(model, "storage.df_inode", status, note)
        if inode_res:
            for line in inode_res.splitlines()[1:]:
                parts = line.split()
                if len(parts) < 6:
                    continue
                mount = parts[-1]
                pct = parts[-2].rstrip("%")
                if pct.replace(".", "", 1).isdigit():
                    inode_pct_by_mount[mount] = float(pct)

        disk_res, status, note = self._run_stdout("df -P -k 2>/dev/null", timeout=8, use_sudo=False, empty_status="not_observed")
        self._record(model, "storage.df_disk", status, note)
        if not disk_res:
            return

        mounts: list[StorageMountModel] = []
        for line in disk_res.splitlines()[1:]:
            parts = line.split()
            if len(parts) < 6:
                continue
            mount = parts[-1]
            total_kb = parts[-5]
            used_kb = parts[-4]
            used_pct = parts[-2].rstrip("%")
            if not (total_kb.isdigit() and used_kb.isdigit() and used_pct.replace(".", "", 1).isdigit()):
                continue
            mounts.append(
                StorageMountModel(
                    mount=mount,
                    total_gb=round(int(total_kb) / (1024 * 1024), 2),
                    used_gb=round(int(used_kb) / (1024 * 1024), 2),
                    used_percent=float(used_pct),
                    inode_used_percent=inode_pct_by_mount.get(mount),
                    read_only=False,
                )
            )
        model.mounts = sorted(mounts, key=lambda m: m.used_percent, reverse=True)

    def _collect_read_only_mounts(self, model: StorageModel) -> None:
        mounts_text, status, note = self._run_stdout("cat /proc/mounts 2>/dev/null", timeout=5, use_sudo=False, empty_status="not_observed")
        self._record(model, "storage.proc_mounts", status, note)
        if not mounts_text:
            return

        read_only: list[str] = []
        for raw in mounts_text.splitlines():
            parts = raw.split()
            if len(parts) < 4:
                continue
            mount = parts[1]
            options = parts[3].split(",")
            if "ro" in options:
                read_only.append(mount)

        ro_set = set(read_only)
        model.read_only_mounts = sorted(ro_set)
        if not model.mounts:
            return
        for mount in model.mounts:
            mount.read_only = mount.mount in ro_set

    def _collect_failed_mount_units(self, model: StorageModel) -> None:
        _, check_status, check_note = self._run_stdout(
            "command -v systemctl 2>/dev/null",
            timeout=3,
            use_sudo=False,
            empty_status="not_supported",
            missing_status="not_supported",
        )
        if check_status != "collected":
            self._record(model, "storage.systemd_failed_mounts", check_status, check_note or "systemctl not available")
            return
        failed, status, note = self._run_stdout(
            "systemctl --failed --type=mount --no-legend 2>/dev/null",
            timeout=6,
            empty_status="not_observed",
        )
        self._record(model, "storage.systemd_failed_mounts", status, note)
        if not failed:
            return
        units: list[str] = []
        for raw in failed.splitlines():
            line = raw.strip()
            if not line:
                continue
            unit = line.split()[0]
            if unit:
                units.append(unit)
        model.failed_mount_units = sorted(set(units))

    def _collect_iowait(self, model: StorageModel) -> None:
        vmstat_line, status, note = self._run_stdout(
            "vmstat 1 2 2>/dev/null | tail -n 1",
            timeout=5,
            use_sudo=False,
            empty_status="not_observed",
        )
        self._record(model, "storage.vmstat_iowait", status, note)
        if not vmstat_line:
            return
        parts = vmstat_line.split()
        if len(parts) < 16:
            return
        # vmstat output ends with "... us sy id wa st"; wa is the second-to-last value.
        try:
            model.io_wait_percent = float(parts[-2])
        except ValueError:
            return

    def _collect_io_errors(self, model: StorageModel) -> None:
        output, status, note = self._run_stdout(
            "dmesg -T 2>/dev/null "
            "| grep -Ei 'i/o error|buffer i/o|ext4-fs error|xfs .*error|blk_update_request' "
            f"| tail -n {self._dmesg_tail_lines}",
            timeout=10,
            empty_status="not_observed",
        )
        self._record(model, "storage.dmesg_io_errors", status, note)
        if not output:
            return
        model.io_error_samples = [line.strip()[:220] for line in output.splitlines() if line.strip()]
