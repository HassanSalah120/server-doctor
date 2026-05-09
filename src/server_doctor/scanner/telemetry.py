"""Telemetry Scanner - Collects host-level performance telemetry.

This scanner gathers lightweight OS metrics that are useful for
infrastructure health checks:
- CPU cores and load average
- Memory and swap usage
- Disk usage by mountpoint
"""

import logging
import os

from server_doctor.connector.ssh import SSHConnector
from server_doctor.model.server import DiskUsage, TelemetryModel


_log = logging.getLogger(__name__)


class TelemetryScanner:
    """Scanner for host telemetry snapshots."""

    def __init__(self, ssh: SSHConnector) -> None:
        self.ssh = ssh

    def _run(self, command: str, timeout: float = 8):
        """Telemetry reads do not require sudo; avoid sudo prompt noise in parser input."""
        return self.ssh.run(command, timeout=timeout, use_sudo=False)

    def _debug_enabled(self) -> bool:
        return os.getenv("server_doctor_DEBUG_TELEMETRY", "0").strip() == "1"

    def _dbg(self, message: str) -> None:
        if self._debug_enabled():
            _log.info("[telemetry] %s", message)

    def scan(self) -> TelemetryModel:
        """Collect telemetry data from the host."""
        telemetry = TelemetryModel()

        self._dbg("scan:start")
        self._collect_cpu_load(telemetry)
        self._collect_memory_swap(telemetry)
        self._collect_disks(telemetry)
        
        # If no data collected, try Docker/cgroup fallbacks
        if not telemetry.cpu_cores:
            self._collect_cpu_docker(telemetry)
        if not telemetry.mem_total_mb:
            self._collect_memory_docker(telemetry)

        self._dbg(
            f"scan:done cpu_cores={telemetry.cpu_cores} load_1={telemetry.load_1} mem_total_mb={telemetry.mem_total_mb} mem_available_mb={telemetry.mem_available_mb} disks={len(telemetry.disks or [])}"
        )
        
        return telemetry

    def _collect_cpu_load(self, telemetry: TelemetryModel) -> None:
        nproc_res = self._run("nproc 2>/dev/null")
        if nproc_res.success and nproc_res.stdout.strip().isdigit():
            telemetry.cpu_cores = int(nproc_res.stdout.strip())

        self._dbg(f"cpu_load:nproc success={nproc_res.success} stdout={nproc_res.stdout.strip()!r}")

        load_res = self._run("cat /proc/loadavg 2>/dev/null")
        if load_res.success and load_res.stdout.strip():
            parts = load_res.stdout.strip().split()
            if len(parts) >= 3:
                try:
                    telemetry.load_1 = float(parts[0])
                    telemetry.load_5 = float(parts[1])
                    telemetry.load_15 = float(parts[2])
                except ValueError:
                    return

        self._dbg(f"cpu_load:loadavg success={load_res.success} stdout={load_res.stdout.strip()!r}")

    def _collect_cpu_docker(self, telemetry: TelemetryModel) -> None:
        """Fallback for Docker containers - use cgroup files."""
        # Try cgroup v2
        cpu_max_res = self._run(
            "cat /sys/fs/cgroup/cpu.max 2>/dev/null || cat /sys/fs/cgroup/cpu/cpu.cfs_quota_us 2>/dev/null"
        )
        self._dbg(f"cpu_docker:cpu_max success={cpu_max_res.success} stdout={cpu_max_res.stdout.strip()!r}")
        if cpu_max_res.success and cpu_max_res.stdout.strip():
            raw = cpu_max_res.stdout.strip()
            parts = raw.split()

            # cgroup v2: "<quota> <period>" (or "max <period>")
            if len(parts) >= 2:
                quota_s, period_s = parts[0], parts[1]
                if quota_s != "max":
                    try:
                        quota = int(quota_s)
                        period = int(period_s)
                        if quota > 0 and period > 0:
                            cores = quota / period
                            telemetry.cpu_cores = max(1, int(round(cores)))
                    except ValueError:
                        pass
            # cgroup v1 quota only (microseconds)
            elif len(parts) == 1:
                try:
                    quota = int(parts[0])
                    if quota > 0:
                        cores = quota / 100000
                        telemetry.cpu_cores = max(1, int(round(cores)))
                except ValueError:
                    pass
        
        # Get online CPUs count as fallback
        if not telemetry.cpu_cores:
            cpu_count_res = self._run("cat /sys/fs/cgroup/cpuset.cpus.effective 2>/dev/null")
            self._dbg(f"cpu_docker:cpuset success={cpu_count_res.success} stdout={cpu_count_res.stdout.strip()!r}")
            if cpu_count_res.success and cpu_count_res.stdout.strip():
                raw = cpu_count_res.stdout.strip()
                # Format: "0-3" or "0,2" or "0-1,4-5".
                total = 0
                for token in raw.split(","):
                    token = token.strip()
                    if not token:
                        continue
                    if "-" in token:
                        a, b = token.split("-", 1)
                        if a.isdigit() and b.isdigit():
                            total += int(b) - int(a) + 1
                    elif token.isdigit():
                        total += 1
                if total > 0:
                    telemetry.cpu_cores = total
        
        # Container load - use 1-min CPU usage percentage if available
        cpu_stat_res = self._run("cat /sys/fs/cgroup/cpu.stat 2>/dev/null | grep usage_usec | head -1")
        self._dbg(f"cpu_docker:cpu_stat success={cpu_stat_res.success} stdout={cpu_stat_res.stdout.strip()!r}")
        if cpu_stat_res.success:
            # Can't easily get load average in containers, leave as None
            pass

    def _collect_memory_swap(self, telemetry: TelemetryModel) -> None:
        # Avoid depending on awk/busybox variants; parse /proc/meminfo directly.
        mem_res = self._run("cat /proc/meminfo 2>/dev/null")
        self._dbg(f"mem:meminfo success={mem_res.success} bytes={len(mem_res.stdout or '')}")
        if not mem_res.success:
            return

        data_kb: dict[str, int] = {}
        for line in mem_res.stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            if ":" not in line:
                continue

            key, rest = line.split(":", 1)
            key = key.strip()
            parts = rest.strip().split()
            if not parts:
                continue
            if parts[0].isdigit():
                data_kb[key] = int(parts[0])

        if "MemTotal" in data_kb:
            telemetry.mem_total_mb = data_kb["MemTotal"] // 1024
        if "MemAvailable" in data_kb:
            telemetry.mem_available_mb = data_kb["MemAvailable"] // 1024
        if "SwapTotal" in data_kb:
            telemetry.swap_total_mb = data_kb["SwapTotal"] // 1024
        if "SwapFree" in data_kb:
            telemetry.swap_free_mb = data_kb["SwapFree"] // 1024

    def _collect_memory_docker(self, telemetry: TelemetryModel) -> None:
        """Fallback for Docker containers - use cgroup memory files."""
        # Try cgroup v2 memory.max
        mem_max_res = self._run("cat /sys/fs/cgroup/memory.max 2>/dev/null || cat /sys/fs/cgroup/memory.limit_in_bytes 2>/dev/null")
        self._dbg(f"mem_docker:memory_max success={mem_max_res.success} stdout={mem_max_res.stdout.strip()!r}")
        if mem_max_res.success and mem_max_res.stdout.strip():
            try:
                raw = mem_max_res.stdout.strip()
                if raw != "max":
                    mem_bytes = int(raw)
                    if mem_bytes > 0 and mem_bytes < 9223372036854771712:  # Not "max"
                        telemetry.mem_total_mb = mem_bytes // (1024 * 1024)
            except ValueError:
                pass

        # If cgroup limit is unlimited, fall back to /proc/meminfo (container view)
        if not telemetry.mem_total_mb:
            meminfo_res = self._run("cat /proc/meminfo 2>/dev/null")
            self._dbg(f"mem_docker:meminfo_total success={meminfo_res.success} bytes={len(meminfo_res.stdout or '')}")
            if meminfo_res.success:
                for line in meminfo_res.stdout.splitlines():
                    if line.startswith("MemTotal:"):
                        parts = line.split()
                        if len(parts) >= 2 and parts[1].isdigit():
                            telemetry.mem_total_mb = int(parts[1]) // 1024
                        break

        # Get current memory usage
        mem_current_res = self._run("cat /sys/fs/cgroup/memory.current 2>/dev/null || cat /sys/fs/cgroup/memory.usage_in_bytes 2>/dev/null")
        self._dbg(f"mem_docker:memory_current success={mem_current_res.success} stdout={mem_current_res.stdout.strip()!r}")
        if mem_current_res.success and mem_current_res.stdout.strip():
            try:
                current_bytes = int(mem_current_res.stdout.strip())
                current_mb = current_bytes // (1024 * 1024)
                if telemetry.mem_total_mb:
                    telemetry.mem_available_mb = max(0, telemetry.mem_total_mb - current_mb)
            except ValueError:
                pass

        # Fallback: use MemAvailable from /proc/meminfo if cgroup current isn't available.
        if telemetry.mem_total_mb and telemetry.mem_available_mb is None:
            meminfo_res = self._run("cat /proc/meminfo 2>/dev/null")
            self._dbg(f"mem_docker:meminfo_available success={meminfo_res.success} bytes={len(meminfo_res.stdout or '')}")
            if meminfo_res.success:
                for line in meminfo_res.stdout.splitlines():
                    if line.startswith("MemAvailable:"):
                        parts = line.split()
                        if len(parts) >= 2 and parts[1].isdigit():
                            available_mb = int(parts[1]) // 1024
                            telemetry.mem_available_mb = min(telemetry.mem_total_mb, available_mb)
                        break

    def _collect_disks(self, telemetry: TelemetryModel) -> None:
        inode_pct_by_mount: dict[str, float] = {}
        inode_total_by_mount: dict[str, int] = {}
        inode_res = self._run("df -P -i 2>/dev/null")
        if inode_res.success:
            for line in inode_res.stdout.splitlines()[1:]:
                parts = line.split()
                if len(parts) < 6:
                    continue
                mount = parts[-1]
                iused = parts[-4]
                ifree = parts[-3]
                iuse_pct = parts[-2].rstrip("%")
                if not (iused.isdigit() and ifree.isdigit() and iuse_pct.replace(".", "", 1).isdigit()):
                    continue
                inode_total_by_mount[mount] = int(iused) + int(ifree)
                inode_pct_by_mount[mount] = float(iuse_pct)

        df_res = self._run("df -P -k 2>/dev/null")
        if not df_res.success:
            return

        disks: list[DiskUsage] = []
        lines = df_res.stdout.splitlines()
        for line in lines[1:]:
            parts = line.split()
            if len(parts) < 6:
                continue

            mount = parts[-1]
            if not mount.startswith("/"):
                continue

            total_kb = parts[-5]
            used_kb = parts[-4]
            use_pct = parts[-2].rstrip("%")

            if not (total_kb.isdigit() and used_kb.isdigit() and use_pct.isdigit()):
                continue

            total_gb = round(int(total_kb) / (1024 * 1024), 2)
            used_gb = round(int(used_kb) / (1024 * 1024), 2)
            used_percent = float(use_pct)

            disks.append(
                DiskUsage(
                    mount=mount,
                    total_gb=total_gb,
                    used_gb=used_gb,
                    used_percent=used_percent,
                    inode_total=inode_total_by_mount.get(mount),
                    inode_used_percent=inode_pct_by_mount.get(mount),
                )
            )

        telemetry.disks = sorted(disks, key=lambda d: d.used_percent, reverse=True)
