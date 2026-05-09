"""Continuous monitoring daemon for server-doctor.

Runs scheduled scans and sends alerts for new or resolved issues.
"""

import json
import logging
import os
import signal
import threading
import time
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

from server_doctor.config import ConfigManager
from server_doctor.connector.ssh import SSHConfig, SSHConnector
from server_doctor.integrations.notifier import NotificationManager

logger = logging.getLogger(__name__)


class MonitoringDaemon:
    """Daemon process for continuous server monitoring."""
    
    def __init__(
        self,
        config_mgr: ConfigManager | None = None,
        interval: int = 3600,
        servers: list[str] | None = None,
        pid_file: str = "/tmp/server-doctor.pid",
        log_file: str | None = None,
    ):
        self.config_mgr = config_mgr or ConfigManager()
        self.interval = interval
        self.servers = servers
        self.pid_file = pid_file
        self.log_file = log_file
        self.running = False
        self.notifier = NotificationManager(self.config_mgr)
        self._state_lock = threading.Lock()

        # State tracking per server
        self.previous_findings: dict[str, list[dict]] = {}
        self.started_at: str | None = None
        self.last_scan: str | None = None
        self.next_scan: str | None = None
        self.scan_count: int = 0
        self.error_count: int = 0
        self.history: list[dict[str, Any]] = []

        # Setup logging
        self._setup_logging()
        self._load_state()
    
    def _setup_logging(self) -> None:
        """Configure logging for daemon mode."""
        handlers = [logging.StreamHandler()]
        
        if self.log_file:
            handlers.append(logging.FileHandler(self.log_file))
        
        logging.basicConfig(
            level=logging.INFO,
            format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
            handlers=handlers,
        )
    
    def start(self) -> None:
        """Start the daemon."""
        if self.is_running():
            logger.error("Daemon is already running")
            raise RuntimeError("Daemon is already running")

        self.started_at = datetime.utcnow().isoformat()
        self.next_scan = self.started_at
        self._save_state()
        self._write_pid()
        self.running = True
        
        logger.info(f"Starting daemon with interval={self.interval}s")
        logger.info(f"Monitoring servers: {self.servers or 'all configured'}")
        
        # Setup signal handlers (Unix only)
        try:
            signal.signal(signal.SIGTERM, self._handle_signal)
            signal.signal(signal.SIGINT, self._handle_signal)
        except (AttributeError, ValueError):
            # Windows doesn't support SIGTERM
            pass
        
        try:
            self._run_loop()
        except Exception as e:
            logger.exception("Daemon loop error")
            raise
        finally:
            self._cleanup()
    
    def _run_loop(self) -> None:
        """Main daemon loop."""
        while self.running:
            start_time = time.time()
            cycle_started = datetime.utcnow()

            try:
                self._run_scan_cycle()
            except Exception as e:
                logger.exception("Scan cycle failed")
                self.error_count += 1
                self._append_history(
                    {
                        "timestamp": datetime.utcnow().isoformat(),
                        "server": "daemon",
                        "status": "error",
                        "message": str(e),
                    }
                )
                self._save_state()

            # Calculate sleep time
            elapsed = time.time() - start_time
            sleep_time = max(0, self.interval - elapsed)
            self.last_scan = cycle_started.isoformat()
            if self.running:
                self.next_scan = (datetime.utcnow() + timedelta(seconds=sleep_time)).isoformat()
            else:
                self.next_scan = None
            self._save_state()

            if self.running and sleep_time > 0:
                logger.debug(f"Sleeping for {sleep_time}s")
                time.sleep(sleep_time)
    
    def _run_scan_cycle(self) -> None:
        """Run one scan cycle for all monitored servers."""
        servers = self._get_servers_to_monitor()
        
        for server_name in servers:
            try:
                self._scan_server(server_name)
            except Exception as e:
                logger.error(f"Failed to scan {server_name}: {e}")
    
    def _get_servers_to_monitor(self) -> list[str]:
        """Get list of servers to monitor."""
        if self.servers:
            return self.servers
        
        # Get all configured profiles
        profiles = self.config_mgr.list_profiles()
        return list(profiles.keys())
    
    def _scan_server(self, server_name: str) -> None:
        """Scan a single server and process findings."""
        logger.info(f"Scanning {server_name}...")
        
        # Load server config
        cfg = self.config_mgr.load_profile(server_name)
        if not cfg:
            logger.warning(f"No config found for {server_name}")
            self.error_count += 1
            self._append_history(
                {
                    "timestamp": datetime.utcnow().isoformat(),
                    "server": server_name,
                    "status": "error",
                    "message": "No config found",
                }
            )
            self._save_state()
            return
        
        # Run scan
        from server_doctor.cli import _run_full_scan
        
        try:
            with SSHConnector(cfg) as ssh:
                findings = _run_full_scan(ssh, cfg, timeout=300)
        except Exception as e:
            logger.error(f"Scan failed for {server_name}: {e}")
            self.error_count += 1
            self._append_history(
                {
                    "timestamp": datetime.utcnow().isoformat(),
                    "server": server_name,
                    "status": "error",
                    "message": f"Scan failed: {e}",
                }
            )
            self._save_state()
            return

        # Convert to comparable format
        current = self._serialize_findings(findings)
        previous = self.previous_findings.get(server_name, [])
        
        # Detect changes
        new_findings = self._detect_new_findings(current, previous)
        resolved_findings = self._detect_resolved_findings(current, previous)
        
        # Update state
        self.previous_findings[server_name] = current
        self.scan_count += 1
        self.last_scan = datetime.utcnow().isoformat()
        self._append_history(
            {
                "timestamp": self.last_scan,
                "server": server_name,
                "status": "success",
                "new_findings": len(new_findings),
                "resolved_findings": len(resolved_findings),
                "findings_total": len(current),
            }
        )
        
        # Save state to disk
        self._save_state()
        
        # Notify about changes
        if new_findings or resolved_findings:
            logger.info(
                f"{server_name}: {len(new_findings)} new, {len(resolved_findings)} resolved"
            )
            self._notify_changes(server_name, new_findings, resolved_findings)
        else:
            logger.debug(f"{server_name}: No changes detected")

    def _append_history(self, event: dict[str, Any]) -> None:
        self.history.append(event)
        # Keep bounded daemon history.
        if len(self.history) > 500:
            self.history = self.history[-500:]
    
    def _serialize_findings(self, findings: list) -> list[dict]:
        """Serialize findings to comparable format."""
        return [
            {
                "id": f.id,
                "severity": f.severity.value,
                "condition": f.condition,
                "cause": f.cause,
            }
            for f in findings
        ]
    
    def _detect_new_findings(
        self, current: list[dict], previous: list[dict]
    ) -> list[dict]:
        """Find new findings that weren't in previous scan."""
        previous_ids = {self._finding_key(f) for f in previous}
        return [f for f in current if self._finding_key(f) not in previous_ids]
    
    def _detect_resolved_findings(
        self, current: list[dict], previous: list[dict]
    ) -> list[dict]:
        """Find resolved findings that were in previous but not current."""
        current_ids = {self._finding_key(f) for f in current}
        return [f for f in previous if self._finding_key(f) not in current_ids]
    
    def _finding_key(self, finding: dict) -> str:
        """Generate unique key for finding comparison."""
        return f"{finding['id']}:{finding['condition']}"
    
    def _notify_changes(
        self,
        server_name: str,
        new: list[dict],
        resolved: list[dict],
    ) -> None:
        """Send notifications about changes."""
        from server_doctor.model.finding import Finding, Severity
        from server_doctor.model.evidence import Evidence
        
        # Convert dicts back to Finding objects for notifier
        new_findings = []
        for f in new:
            try:
                severity = Severity(f["severity"])
            except ValueError:
                severity = Severity.INFO
            
            finding = Finding(
                id=f["id"],
                severity=severity,
                confidence=0.8,
                condition=f"[NEW] {f['condition']}",
                cause=f["cause"],
                evidence=[Evidence(source_file="daemon", line_number=1, excerpt="", command="")],
            )
            new_findings.append(finding)
        
        if new_findings:
            self.notifier.send_notification(
                new_findings,
                server_name=server_name,
                only_critical=False,
            )
    
    def _save_state(self) -> None:
        """Save daemon state to disk."""
        with self._state_lock:
            state = {
                "previous_findings": self.previous_findings,
                "started_at": self.started_at,
                "last_scan": self.last_scan,
                "next_scan": self.next_scan,
                "scan_count": self.scan_count,
                "error_count": self.error_count,
                "history": self.history,
                "last_update": datetime.utcnow().isoformat(),
                "interval": self.interval,
                "servers": self.servers or "all",
            }

            state_file = Path(self.pid_file).parent / "server-doctor-state.json"
            state_file.write_text(json.dumps(state, indent=2))
    
    def _load_state(self) -> None:
        """Load daemon state from disk."""
        state_file = Path(self.pid_file).parent / "server-doctor-state.json"
        
        if state_file.exists():
            try:
                with self._state_lock:
                    state = json.loads(state_file.read_text())
                    self.previous_findings = state.get("previous_findings", {})
                    self.started_at = state.get("started_at")
                    self.last_scan = state.get("last_scan")
                    self.next_scan = state.get("next_scan")
                    self.scan_count = int(state.get("scan_count", 0) or 0)
                    self.error_count = int(state.get("error_count", 0) or 0)
                    interval_val = state.get("interval")
                    if isinstance(interval_val, int) and interval_val > 0:
                        self.interval = interval_val
                    servers_val = state.get("servers")
                    if isinstance(servers_val, list):
                        self.servers = [str(s) for s in servers_val]
                    elif servers_val == "all":
                        self.servers = None
                    raw_history = state.get("history") or []
                    self.history = raw_history if isinstance(raw_history, list) else []
            except Exception as e:
                logger.warning(f"Failed to load state: {e}")
    
    def stop(self) -> None:
        """Stop the daemon."""
        logger.info("Stopping daemon...")
        self.running = False
        self.next_scan = None
        self._save_state()
        self._cleanup()
    
    def _cleanup(self) -> None:
        """Cleanup resources."""
        self._remove_pid()
        logger.info("Daemon stopped")
    
    def _handle_signal(self, signum: int, frame: Any) -> None:
        """Handle shutdown signals."""
        logger.info(f"Received signal {signum}")
        self.stop()
    
    def _write_pid(self) -> None:
        """Write PID file."""
        pid_path = Path(self.pid_file)
        pid_path.parent.mkdir(parents=True, exist_ok=True)
        pid_path.write_text(str(os.getpid()))
    
    def _remove_pid(self) -> None:
        """Remove PID file."""
        try:
            Path(self.pid_file).unlink()
        except FileNotFoundError:
            pass

    def get_info(self) -> dict[str, Any]:
        """Get daemon runtime info.

        Note: this does not guarantee the daemon loop is healthy, only that the PID exists.
        """
        self._load_state()
        pid_file = Path(self.pid_file)
        pid: int | None = None
        if pid_file.exists():
            try:
                pid = int(pid_file.read_text().strip())
            except ValueError:
                pid = None

        return {
            "pid": pid,
            "servers": self.servers or "all",
            "interval": self.interval,
            "started_at": self.started_at,
            "last_scan": self.last_scan,
            "next_scan": self.next_scan,
            "scan_count": self.scan_count,
            "error_count": self.error_count,
        }

    def get_history(self, limit: int = 10) -> list[dict[str, Any]]:
        """Get recent daemon scan/activity history."""
        self._load_state()
        if limit <= 0:
            return []
        return list(reversed(self.history[-limit:]))
    
    def is_running(self) -> bool:
        """Check if daemon is running."""
        pid_file = Path(self.pid_file)
        if not pid_file.exists():
            return False

        try:
            pid = int(pid_file.read_text().strip())

            if os.name == "nt":
                import ctypes

                PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
                handle = ctypes.windll.kernel32.OpenProcess(
                    PROCESS_QUERY_LIMITED_INFORMATION, False, pid
                )
                if handle:
                    ctypes.windll.kernel32.CloseHandle(handle)
                    return True
                raise ProcessLookupError()

            os.kill(pid, 0)
            return True
        except (ValueError, OSError, ProcessLookupError):
            # Stale / invalid PID file
            self._cleanup()
            return False
