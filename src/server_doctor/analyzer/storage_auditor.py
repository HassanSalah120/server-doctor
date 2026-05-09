"""Storage Auditor - Checks mount health, read-only state, and IO pressure."""

from __future__ import annotations

from server_doctor.engine.runtime_thresholds import env_float
from server_doctor.model.evidence import Evidence, Severity
from server_doctor.model.finding import Finding
from server_doctor.model.server import ServerModel


class StorageAuditor:
    """Auditor for storage and mount reliability posture."""

    _RO_IGNORE_PREFIXES = (
        "/proc",
        "/sys",
        "/dev",
        "/run",
        "/snap",
    )

    def __init__(self, model: ServerModel) -> None:
        self.model = model
        self._disk_warn = env_float("server_doctor_STORAGE_DISK_WARN_PERCENT", 92.0, min_value=10.0, max_value=99.0)
        self._disk_crit = env_float("server_doctor_STORAGE_DISK_CRIT_PERCENT", 97.0, min_value=self._disk_warn, max_value=100.0)
        self._inode_warn = env_float("server_doctor_STORAGE_INODE_WARN_PERCENT", 92.0, min_value=10.0, max_value=99.0)
        self._inode_crit = env_float("server_doctor_STORAGE_INODE_CRIT_PERCENT", 97.0, min_value=self._inode_warn, max_value=100.0)
        self._iowait_warn = env_float("server_doctor_STORAGE_IOWAIT_WARN_PERCENT", 20.0, min_value=1.0, max_value=99.0)
        self._iowait_crit = env_float("server_doctor_STORAGE_IOWAIT_CRIT_PERCENT", 40.0, min_value=self._iowait_warn, max_value=100.0)

    def audit(self) -> list[Finding]:
        if not hasattr(self.model, "storage"):
            return []

        findings: list[Finding] = []
        findings.extend(self._check_disk_exhaustion())
        findings.extend(self._check_inode_exhaustion())
        findings.extend(self._check_read_only_mounts())
        findings.extend(self._check_failed_mount_units())
        findings.extend(self._check_iowait_pressure())
        findings.extend(self._check_kernel_io_errors())
        return findings

    def _check_disk_exhaustion(self) -> list[Finding]:
        hot = [m for m in (self.model.storage.mounts or []) if m.used_percent >= self._disk_warn]
        if not hot:
            return []
        max_used = max(m.used_percent for m in hot)
        severity = Severity.CRITICAL if max_used >= self._disk_crit else Severity.WARNING
        return [
            Finding(
                id="STOR-1",
                severity=severity,
                confidence=0.9,
                condition=f"{len(hot)} mountpoint(s) approaching disk exhaustion",
                cause="Storage scan detected critically high disk utilization on one or more mounts.",
                evidence=[
                    Evidence(
                        source_file=hot[0].mount,
                        line_number=1,
                        excerpt=f"{hot[0].used_percent:.1f}% used ({hot[0].used_gb:.2f}GB/{hot[0].total_gb:.2f}GB)",
                        command="df -P -k",
                    )
                ],
                treatment="Free space or expand storage before write-path failures occur.",
                impact=[
                    "Write failures and degraded service stability",
                ],
            )
        ]

    def _check_inode_exhaustion(self) -> list[Finding]:
        hot = [
            m for m in (self.model.storage.mounts or [])
            if m.inode_used_percent is not None and m.inode_used_percent >= self._inode_warn
        ]
        if not hot:
            return []
        max_used = max(m.inode_used_percent or 0.0 for m in hot)
        severity = Severity.CRITICAL if max_used >= self._inode_crit else Severity.WARNING
        first = hot[0]
        return [
            Finding(
                id="STOR-2",
                severity=severity,
                confidence=0.86,
                condition=f"{len(hot)} mountpoint(s) approaching inode exhaustion",
                cause="Filesystem inode consumption is critically high.",
                evidence=[
                    Evidence(
                        source_file=first.mount,
                        line_number=1,
                        excerpt=f"inode usage={first.inode_used_percent:.1f}%",
                        command="df -P -i",
                    )
                ],
                treatment="Clean up high-file-count paths or increase inode capacity.",
                impact=[
                    "File creation can fail despite available disk space",
                ],
            )
        ]

    def _check_read_only_mounts(self) -> list[Finding]:
        read_only = [
            m for m in (self.model.storage.read_only_mounts or [])
            if m and not any(m.startswith(prefix) for prefix in self._RO_IGNORE_PREFIXES)
        ]
        if not read_only:
            return []
        return [
            Finding(
                id="STOR-3",
                severity=Severity.WARNING,
                confidence=0.8,
                condition=f"Unexpected read-only mount(s) detected ({len(read_only)})",
                cause="One or more non-pseudo filesystems are mounted read-only.",
                evidence=[
                    Evidence(
                        source_file="/proc/mounts",
                        line_number=1,
                        excerpt=", ".join(read_only[:4]),
                        command="cat /proc/mounts",
                    )
                ],
                treatment="Investigate filesystem remount causes and restore read-write state where required.",
                impact=[
                    "Application writes, logs, and temp files may fail",
                ],
            )
        ]

    def _check_failed_mount_units(self) -> list[Finding]:
        failed = self.model.storage.failed_mount_units or []
        if not failed:
            return []
        return [
            Finding(
                id="STOR-4",
                severity=Severity.WARNING,
                confidence=0.88,
                condition=f"Failed systemd mount unit(s) detected ({len(failed)})",
                cause="Systemd reports failed mount units.",
                evidence=[
                    Evidence(
                        source_file="systemd",
                        line_number=1,
                        excerpt=", ".join(failed[:4]),
                        command="systemctl --failed --type=mount --no-legend",
                    )
                ],
                treatment="Fix mount unit configuration/state and verify required filesystems are available at boot.",
                impact=[
                    "Missing filesystems can break dependent services",
                ],
            )
        ]

    def _check_iowait_pressure(self) -> list[Finding]:
        iowait = self.model.storage.io_wait_percent
        if iowait is None or iowait < self._iowait_warn:
            return []
        severity = Severity.CRITICAL if iowait >= self._iowait_crit else Severity.WARNING
        return [
            Finding(
                id="STOR-5",
                severity=severity,
                confidence=0.74,
                condition=f"Elevated IO wait detected ({iowait:.1f}%)",
                cause="Host CPU is spending significant time waiting on storage I/O.",
                evidence=[
                    Evidence(
                        source_file="vmstat",
                        line_number=1,
                        excerpt=f"wa={iowait:.1f}%",
                        command="vmstat 1 2",
                    )
                ],
                treatment="Inspect storage latency and high-IO workloads; optimize or isolate noisy paths.",
                impact=[
                    "Request latency and queueing increase under load",
                ],
            )
        ]

    def _check_kernel_io_errors(self) -> list[Finding]:
        samples = self.model.storage.io_error_samples or []
        if not samples:
            return []
        return [
            Finding(
                id="STOR-6",
                severity=Severity.WARNING,
                confidence=0.86,
                condition=f"Kernel/filesystem I/O errors detected ({len(samples)} recent entries)",
                cause="Kernel log contains block/filesystem I/O error signatures.",
                evidence=[
                    Evidence(
                        source_file="dmesg",
                        line_number=1,
                        excerpt=samples[0][:220],
                        command="dmesg -T | egrep -i 'i/o error|ext4-fs error|xfs .*error'",
                    )
                ],
                treatment="Validate underlying storage health and run filesystem/device diagnostics.",
                impact=[
                    "Potential data integrity and availability risk",
                ],
            )
        ]
