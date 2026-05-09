"""Telemetry Auditor - Host resource pressure checks."""

from server_doctor.model.evidence import Evidence, Severity
from server_doctor.model.finding import Finding
from server_doctor.model.server import ServerModel


class TelemetryAuditor:
    """Auditor for CPU/load, memory, swap, and disk pressure."""

    def __init__(self, model: ServerModel) -> None:
        self.model = model

    def audit(self) -> list[Finding]:
        """Run telemetry checks."""
        findings: list[Finding] = []

        if not hasattr(self.model, "telemetry"):
            return findings

        findings.extend(self._check_load())
        findings.extend(self._check_memory())
        findings.extend(self._check_swap())
        findings.extend(self._check_disk())
        findings.extend(self._check_inode_pressure())
        return findings

    def _check_load(self) -> list[Finding]:
        telemetry = self.model.telemetry
        if telemetry.load_1 is None or telemetry.cpu_cores is None or telemetry.cpu_cores <= 0:
            return []

        ratio = telemetry.load_1 / telemetry.cpu_cores
        if ratio < 1.25:
            return []

        severity = Severity.CRITICAL if ratio >= 2.0 else Severity.WARNING
        return [
            Finding(
                id="HOST-CPU-1",
                severity=severity,
                confidence=0.90,
                condition="High CPU load relative to core count",
                cause=(
                    f"Load average is {telemetry.load_1:.2f} on {telemetry.cpu_cores} cores "
                    f"(ratio {ratio:.2f})."
                ),
                evidence=[
                    Evidence(
                        source_file="/proc/loadavg",
                        line_number=1,
                        excerpt=f"load1={telemetry.load_1}, cores={telemetry.cpu_cores}",
                        command="cat /proc/loadavg; nproc",
                    )
                ],
                treatment="Inspect top CPU consumers and tune worker concurrency or scale capacity.",
                impact=[
                    "Slow response times and request queueing",
                    "Increased risk of upstream timeouts under load",
                ],
            )
        ]

    def _check_memory(self) -> list[Finding]:
        telemetry = self.model.telemetry
        if (
            telemetry.mem_total_mb is None
            or telemetry.mem_total_mb <= 0
            or telemetry.mem_available_mb is None
        ):
            return []

        available_pct = (telemetry.mem_available_mb / telemetry.mem_total_mb) * 100.0
        if available_pct >= 20:
            return []

        severity = Severity.CRITICAL if available_pct < 10 else Severity.WARNING
        return [
            Finding(
                id="HOST-MEM-1",
                severity=severity,
                confidence=0.92,
                condition="Low available memory",
                cause=(
                    f"Available memory is {telemetry.mem_available_mb}MB of "
                    f"{telemetry.mem_total_mb}MB ({available_pct:.1f}%)."
                ),
                evidence=[
                    Evidence(
                        source_file="/proc/meminfo",
                        line_number=1,
                        excerpt=f"MemAvailable={telemetry.mem_available_mb}MB",
                        command="awk '/MemTotal|MemAvailable/ {print}' /proc/meminfo",
                    )
                ],
                treatment="Reduce memory pressure (tune workers/cache) or increase RAM.",
                impact=[
                    "OOM kills and process instability",
                    "Request latency spikes from reclaim pressure",
                ],
            )
        ]

    def _check_swap(self) -> list[Finding]:
        telemetry = self.model.telemetry
        if (
            telemetry.swap_total_mb is None
            or telemetry.swap_total_mb <= 0
            or telemetry.swap_free_mb is None
        ):
            return []

        used_pct = ((telemetry.swap_total_mb - telemetry.swap_free_mb) / telemetry.swap_total_mb) * 100.0
        if used_pct < 80:
            return []

        severity = Severity.CRITICAL if used_pct >= 95 else Severity.WARNING
        return [
            Finding(
                id="HOST-SWAP-1",
                severity=severity,
                confidence=0.88,
                condition="High swap utilization",
                cause=f"Swap usage is {used_pct:.1f}% ({telemetry.swap_total_mb - telemetry.swap_free_mb}MB used).",
                evidence=[
                    Evidence(
                        source_file="/proc/meminfo",
                        line_number=1,
                        excerpt=f"SwapUsed={telemetry.swap_total_mb - telemetry.swap_free_mb}MB",
                        command="awk '/SwapTotal|SwapFree/ {print}' /proc/meminfo",
                    )
                ],
                treatment="Lower memory footprint or increase RAM to avoid sustained swapping.",
                impact=[
                    "Significant latency from disk-backed memory access",
                    "Higher timeout risk during traffic spikes",
                ],
            )
        ]

    def _check_disk(self) -> list[Finding]:
        telemetry = self.model.telemetry
        hot_disks = [d for d in telemetry.disks if d.used_percent >= 85.0]
        if not hot_disks:
            return []

        max_used = max(d.used_percent for d in hot_disks)
        severity = Severity.CRITICAL if max_used >= 95.0 else Severity.WARNING
        evidence = [
            Evidence(
                source_file=d.mount,
                line_number=1,
                excerpt=f"{d.used_percent:.1f}% used ({d.used_gb:.2f}GB/{d.total_gb:.2f}GB)",
                command="df -P -k",
            )
            for d in hot_disks[:5]
        ]

        return [
            Finding(
                id="HOST-DISK-1",
                severity=severity,
                confidence=0.95,
                condition=f"{len(hot_disks)} mountpoint(s) are near disk exhaustion",
                cause="Disk usage exceeded the safe threshold (>=85%).",
                evidence=evidence,
                treatment="Free space, rotate logs, or expand disk capacity before writes fail.",
                impact=[
                    "Write failures for logs/uploads/sockets",
                    "Service crashes and failed deployments",
                ],
            )
        ]

    def _check_inode_pressure(self) -> list[Finding]:
        telemetry = self.model.telemetry
        hot_inodes = [d for d in telemetry.disks if d.inode_used_percent is not None and d.inode_used_percent >= 85.0]
        if not hot_inodes:
            return []

        max_used = max(d.inode_used_percent or 0.0 for d in hot_inodes)
        severity = Severity.CRITICAL if max_used >= 95.0 else Severity.WARNING
        evidence = [
            Evidence(
                source_file=d.mount,
                line_number=1,
                excerpt=f"inode usage {d.inode_used_percent:.1f}% (total={d.inode_total or 'unknown'})",
                command="df -P -i",
            )
            for d in hot_inodes[:5]
        ]

        return [
            Finding(
                id="HOST-DISK-2",
                severity=severity,
                confidence=0.90,
                condition=f"{len(hot_inodes)} mountpoint(s) have high inode usage",
                cause="Filesystem inode utilization exceeded the safe threshold (>=85%).",
                evidence=evidence,
                treatment="Clean up small-file sprawl or increase filesystem inode capacity.",
                impact=[
                    "File creation can fail even when disk space appears available",
                    "Logs/uploads/tmp files may stop working",
                ],
            )
        ]
