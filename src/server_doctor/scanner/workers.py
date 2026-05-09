"""Worker Scanner - Detects background job workers and schedulers.

Identifies Laravel queue workers, Horizon supervisors, and Node.js job consumers.
Also checks for scheduler triggers (Cron or Systemd timers).
"""

from dataclasses import dataclass, field

from server_doctor.connector.ssh import SSHConnector
from server_doctor.model.server import (
    CapabilityLevel,
    CapabilityReason,
    ServiceState,
    ServiceStatus,
    WorkerProcess,
)


@dataclass
class WorkerScanResult:
    """Raw Worker scan results."""

    status: ServiceStatus
    processes: list[WorkerProcess] = field(default_factory=list)
    scheduler_detected: bool = False
    scheduler_type: str | None = None  # cron, systemd-timer


class WorkerScanner:
    """Scanner for background workers.

    Collects:
    - Laravel queue:work / horizon processes
    - Node.js worker processes
    - Scheduler presence (cron/systemd)
    """

    def __init__(self, ssh: SSHConnector) -> None:
        self.ssh = ssh

    def scan(self) -> WorkerScanResult:
        """Perform full Worker and Scheduler scan."""
        # 1. Find worker processes
        processes = self._find_workers()
        
        # 2. Check for scheduler
        scheduler_detected, scheduler_type = self._check_scheduler()
        
        return WorkerScanResult(
            status=ServiceStatus(
                capability=CapabilityLevel.FULL,
                state=ServiceState.RUNNING if processes else ServiceState.STOPPED
            ),
            processes=processes,
            scheduler_detected=scheduler_detected,
            scheduler_type=scheduler_type
        )

    def _find_workers(self) -> list[WorkerProcess]:
        """Find running worker processes."""
        workers = []
        
        # We need command line arguments to distinguish workers
        # ps aux ensures we see them
        cmd = "ps aux --no-headers"
        result = self.ssh.run(cmd)
        
        if not result.success:
            return []

        for line in result.stdout.splitlines():
            # USER PID %CPU %MEM VSZ RSS TTY STAT START TIME COMMAND
            parts = line.split(maxsplit=10)
            if len(parts) < 11:
                continue
                
            pid_str = parts[1]
            try:
                pid = int(pid_str)
            except ValueError:
                continue
                
            cmdline = parts[10]
            
            # Check for Laravel Queue
            if "artisan queue:work" in cmdline or "artisan horizon" in cmdline:
                # Infer backend
                backend = "unknown"
                if "redis" in cmdline:
                    backend = "redis"
                elif "database" in cmdline:
                    backend = "db"
                elif "sqs" in cmdline:
                    backend = "sqs"
                elif "beanstalkd" in cmdline:
                    backend = "beanstalkd"
                
                workers.append(WorkerProcess(
                    pid=pid,
                    cmdline=cmdline,
                    queue_type="laravel",
                    backend=backend
                ))
            
            # Check for Node.js workers (heuristic)
            # Typically "node worker.js", "node dist/worker.js", or process name changes
            # We can also look for "bull" or "bullmq" in cmdline if passed as args, 
            # but usually it's just a node script.
            # Best effort: check for "worker" in node cmdline
            elif "node " in cmdline and ("worker" in cmdline or "consumer" in cmdline or "queue" in cmdline):
                workers.append(WorkerProcess(
                    pid=pid,
                    cmdline=cmdline,
                    queue_type="node",
                    backend="unknown"  # Hard to infer from cmdline for node
                ))
            
            # Check for PM2 managed processes (pm2 often wraps them)
            # PM2 processes appear as "PM2 vX.X.X: <app_name>" sometimes? 
            # Or just node processes but with PM2 env vars.
            # We skip specific PM2 logic for now as ps aux shows the node process usually.
            
        return workers

    def _check_scheduler(self) -> tuple[bool, str | None]:
        """Check for scheduler (Cron or Systemd Timer)."""
        # 1. Check Cron
        # Check running cron daemon first? Not irrelevant if crontabs exist.
        
        # Check specific laravel schedule call in crontab?
        # That would be rigorous. But generic scheduler check?
        # Plan says: "Checks /etc/crontab, crontab -l, and systemd timers"
        
        # Check user crontabs (root and others if possible)
        # Iterate over /var/spool/cron/crontabs/ ? 
        # Safer: checks for artisan schedule:run in crontabs we can read
        
        cron_files = [
            "/etc/crontab",
        ]
        # scan /etc/cron.d
        cron_d_res = self.ssh.list_dir("/etc/cron.d")
        for f in cron_d_res:
            cron_files.append(f"/etc/cron.d/{f}")
            
        found_cron = False
        
        # Check files
        for f in cron_files:
            content = self.ssh.read_file(f)
            if content and "artisan schedule:run" in content:
                return True, "cron"
        
        # Check root crontab
        res = self.ssh.run("crontab -l")
        if res.success and "artisan schedule:run" in res.stdout:
            return True, "cron"
            
        # 2. Check Systemd Timers
        # Look for active timers
        if self.ssh.run("which systemctl").success:
            res = self.ssh.run("systemctl list-timers --all --no-pager")
            if res.success and ("artisan" in res.stdout or "scheduler" in res.stdout):
                # Loose matching, but detecting if *any* scheduler is running
                # Ideally we match the project path.
                return True, "systemd-timer"
                
        return False, None
