"""Worker Auditor - Audits background job worker configuration."""

from server_doctor.model.evidence import Evidence, Severity
from server_doctor.model.finding import Finding
from server_doctor.model.server import ServerModel


class WorkerAuditor:
    """Auditor for background workers and scheduler wiring."""

    def __init__(self, model: ServerModel) -> None:
        self.model = model

    def audit(self) -> list[Finding]:
        """Run all Worker diagnostics."""
        findings: list[Finding] = []

        if not hasattr(self.model, "runtime") or not self.model.runtime.worker_processes:
            return findings

        findings.extend(self._check_schedulers())
        findings.extend(self._check_orphans())
        return findings

    def _check_schedulers(self) -> list[Finding]:
        """WORKER-1: Laravel workers should have a scheduler trigger."""
        has_laravel_workers = any(w.queue_type == "laravel" for w in self.model.runtime.worker_processes)
        if not has_laravel_workers:
            return []

        if self.model.runtime.scheduler_detected:
            return []

        return [
            Finding(
                id="WORKER-1",
                severity=Severity.WARNING,
                confidence=0.90,
                condition="Laravel queue workers detected but no scheduler found",
                cause="Worker processes are running but no cron job or systemd timer appears to invoke 'schedule:run'.",
                evidence=[
                    Evidence(
                        source_file="crontab/systemd",
                        line_number=1,
                        excerpt="Missing 'artisan schedule:run'",
                        command="crontab -l; systemctl list-timers --all",
                    )
                ],
                treatment=(
                    "Configure a scheduler trigger, for example:\n"
                    "    * * * * * php /path/to/artisan schedule:run >> /dev/null 2>&1"
                ),
                impact=[
                    "Scheduled tasks will not run",
                    "Maintenance/cleanup jobs will drift",
                ],
            )
        ]

    def _check_orphans(self) -> list[Finding]:
        """WORKER-2: Detect workers not mapped to systemd-managed units."""
        if not self.model.runtime.systemd_services:
            # Without service metadata we cannot reliably classify orphans.
            return []

        managed_pids = {svc.main_pid for svc in self.model.runtime.systemd_services if svc.main_pid}
        if not managed_pids:
            # We have service rows but no PID metadata, so orphan inference would be noisy.
            return []
        orphan_workers = [w for w in self.model.runtime.worker_processes if w.pid not in managed_pids]

        if not orphan_workers:
            return []

        severity = Severity.WARNING if any(w.queue_type == "laravel" for w in orphan_workers) else Severity.INFO
        evidence = [
            Evidence(
                source_file="ps",
                line_number=1,
                excerpt=f"pid={w.pid} cmd={w.cmdline[:120]}",
                command="ps aux --no-headers",
            )
            for w in orphan_workers[:5]
        ]

        return [
            Finding(
                id="WORKER-2",
                severity=severity,
                confidence=0.70,
                condition=f"{len(orphan_workers)} worker process(es) appear unmanaged",
                cause="No matching systemd MainPID was found for these worker processes.",
                evidence=evidence,
                treatment=(
                    "Run workers under a process manager (systemd, supervisor, or PM2) "
                    "to ensure restart and boot persistence."
                ),
                impact=[
                    "Workers may stop after shell logout/reboot/crash",
                    "Queue throughput may become unpredictable",
                ],
            )
        ]
