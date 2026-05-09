"""DB-backed scan job runner with ThreadPoolExecutor.

Executes scan jobs in background threads, logging progress to SQLite.
max_workers=1 by default (SSH scans are heavy). Configurable via
server_doctor_MAX_WORKERS environment variable.
"""

import json
import os
import time
import traceback
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any

from server_doctor.ai.diagnoser import generate_diagnosis
from server_doctor.connector.ssh import SSHConfig, SSHConnector
from server_doctor.engine.regression import record_scan_lifecycle_events
from server_doctor.storage.repositories import (
    CorrelationRepository,
    FindingRepository,
    JobLogRepository,
    ScanJobRepository,
    ServerRepository,
)
from server_doctor.web.secrets import (
    SecretStorageError,
    get_server_key_passphrase,
    get_server_password,
)


class JobCancelledError(Exception):
    """Raised when a job is requested to be cancelled."""
    pass

class JobTimeoutError(Exception):
    """Raised when a job exceeds the maximum execution time."""
    pass



# Report output directory (under ./data/reports/ to avoid mixing with repo root)
_REPORTS_DIR = Path("./data/reports")

SCAN_PHASES = [
    ("connect", "Connecting over SSH", 5),
    ("os_services", "Detecting OS and services", 15),
    ("nginx", "Reading Nginx config", 30),
    ("apps", "Detecting applications", 45),
    ("security", "Checking security posture", 60),
    ("runtime", "Checking runtime health", 75),
    ("findings", "Building findings", 88),
    ("report", "Generating report", 97),
    ("done", "Done", 100),
]


def _get_max_workers() -> int:
    """Get max workers from env var, default 1."""
    try:
        return int(os.getenv("SERVER_DOCTOR_MAX_WORKERS", "1"))
    except ValueError:
        return 1


class ScanJobRunner:
    """Background scan job runner backed by SQLite storage.

    Submits scan jobs to a thread pool, tracks status and logs in the DB.
    """

    def __init__(self) -> None:
        self._executor = ThreadPoolExecutor(
            max_workers=_get_max_workers(),
            thread_name_prefix="scan-job",
        )
        self._server_repo = ServerRepository()
        self._job_repo = ScanJobRepository()
        self._finding_repo = FindingRepository()
        self._correlation_repo = CorrelationRepository()
        self._log_repo = JobLogRepository()

    def submit_scan(
        self,
        server_id: int,
        repo_scan_paths: str | None = None,
        one_time_password: str | None = None,
        one_time_key_passphrase: str | None = None,
    ) -> int:
        """Submit a scan job for a server. Returns the job ID."""
        # Verify server exists
        server = self._server_repo.get_by_id(server_id)
        if server is None:
            raise ValueError(f"Server with ID {server_id} not found")

        job_id = self._job_repo.create(server_id, repo_scan_paths=repo_scan_paths)
        self._log_repo.append(job_id, "Job queued")
        self._executor.submit(
            self._run_scan,
            job_id,
            server_id,
            repo_scan_paths,
            one_time_password,
            one_time_key_passphrase,
        )
        return job_id

    def _run_scan(
        self,
        job_id: int,
        server_id: int,
        repo_scan_paths: str | None = None,
        one_time_password: str | None = None,
        one_time_key_passphrase: str | None = None,
    ) -> None:
        """Worker function: execute the full scan pipeline."""
        start_time = time.time()
        try:
            # <= 0 disables the hard job timeout.
            job_timeout = int(os.getenv("SERVER_DOCTOR_JOB_TIMEOUT", "0"))
        except ValueError:
            job_timeout = 0

        phases = self._initial_phases()
        active_phase_key: str | None = None

        def write_phases() -> None:
            self._job_repo.update_status(job_id, phases_json=json.dumps(phases, default=str))

        def mark_phase(key: str, status: str = "running", error: str | None = None) -> None:
            nonlocal active_phase_key
            now = self._now()
            active_phase_key = key
            for phase in phases:
                if phase["key"] != key:
                    continue
                phase["status"] = status
                if status == "running" and not phase.get("started_at"):
                    phase["started_at"] = now
                if status in {"success", "failed", "skipped", "cancelled"}:
                    phase["finished_at"] = now
                if error:
                    phase["error"] = error
                self._job_repo.update_status(job_id, progress=int(phase["progress"]))
                break
            write_phases()

        def finish_before(next_key: str) -> None:
            for phase in phases:
                if phase["key"] == next_key:
                    break
                if phase["status"] == "running":
                    phase["status"] = "success"
                    phase["finished_at"] = self._now()
            write_phases()

        def check_status() -> None:
            """Check if job was cancelled or timed out."""
            job = self._job_repo.get_by_id(job_id)
            if job and job.status == "cancel_requested":
                raise JobCancelledError("Job was cancelled by user")
            if job_timeout > 0 and time.time() - start_time > job_timeout:
                raise JobTimeoutError(
                    f"Job exceeded configured timeout of {job_timeout} seconds"
                )

        try:
            self._job_repo.update_status(job_id, "running", progress=0)
            write_phases()
            self._log_repo.append(job_id, "Job started")
            if job_timeout > 0:
                self._log_repo.append(job_id, f"Job timeout configured: {job_timeout}s")
            else:
                self._log_repo.append(job_id, "Job timeout configured: disabled")
            check_status()

            # Load server details
            server = self._server_repo.get_by_id(server_id)
            if server is None:
                raise ValueError(f"Server {server_id} not found")

            self._log_repo.append(
                job_id, f"Connecting to {server.username}@{server.host}:{server.port}..."
            )
            mark_phase("connect")

            auth_mode = "agent/default keys"
            resolved_password = one_time_password
            if resolved_password:
                auth_mode = "one-time password"
            elif server.password_secret_ref:
                try:
                    resolved_password = get_server_password(server.password_secret_ref)
                except SecretStorageError as exc:
                    raise RuntimeError(str(exc)) from exc
                auth_mode = "keyring password" if resolved_password else "keyring password missing"
            elif server.password:
                resolved_password = server.password
                auth_mode = "legacy password"
            if server.key_path:
                auth_mode = "key_path"
            resolved_passphrase = one_time_key_passphrase
            if not resolved_passphrase and server.key_passphrase_secret_ref:
                try:
                    resolved_passphrase = get_server_key_passphrase(
                        server.key_passphrase_secret_ref
                    )
                except SecretStorageError as exc:
                    raise RuntimeError(str(exc)) from exc
            if server.key_path and resolved_passphrase:
                auth_mode = "key_path + passphrase"
            self._log_repo.append(job_id, f"SSH auth mode: {auth_mode}")

            # Build SSH config
            ssh_config = SSHConfig(
                host=server.host,
                user=server.username,
                port=server.port,
                password=resolved_password,
                key_path=server.key_path,
                passphrase=resolved_passphrase,
            )

            # Progress logger
            def log_fn(msg: str) -> None:
                self._log_repo.append(job_id, msg)
                check_status()

            # Execute scan pipeline
            from server_doctor.pipeline import run_full_diagnosis, run_full_scan

            with SSHConnector(ssh_config) as ssh:
                log_fn("SSH connection established")
                mark_phase("connect", "success")
                self._job_repo.update_status(job_id, progress=10)

                # Phase 1: Scan
                mark_phase("os_services")
                log_fn("Starting infrastructure scan...")
                log_fn("DevOps checks enabled (always-on)")
                if repo_scan_paths:
                    log_fn(f"Repo scan paths: {repo_scan_paths}")
                else:
                    log_fn("Repo scan paths: auto-discovery")
                try:
                    model = run_full_scan(
                        ssh,
                        log_fn=log_fn,
                        repo_scan_paths=repo_scan_paths,
                        progress_fn=lambda pct: self._progress_to_phase(job_id, phases, pct),
                    )
                except TypeError as exc:
                    if "progress_fn" not in str(exc):
                        raise
                    model = run_full_scan(
                        ssh,
                        log_fn=log_fn,
                        repo_scan_paths=repo_scan_paths,
                    )
                finish_before("security")
                self._job_repo.update_status(job_id, progress=40)

                # Phase 2: Diagnose
                mark_phase("security")
                log_fn("Running analysis and diagnosis...")
                try:
                    result = run_full_diagnosis(
                        model,
                        ssh,
                        log_fn=log_fn,
                        devops_enabled=True,
                        progress_fn=lambda pct: self._progress_to_phase(job_id, phases, pct),
                    )
                except TypeError as exc:
                    if "progress_fn" not in str(exc):
                        raise
                    result = run_full_diagnosis(
                        model,
                        ssh,
                        log_fn=log_fn,
                        devops_enabled=True,
                    )
                finish_before("findings")
                self._job_repo.update_status(job_id, progress=70)

                # Phase 3: Generate HTML report
                mark_phase("report")
                log_fn("Generating HTML report...")
                report_path = self._generate_report(
                    job_id, model, result, log_fn
                )
                self._job_repo.update_status(job_id, progress=85)

                # Phase 4: AI diagnosis
                log_fn("Generating AI diagnosis...")
                diagnosis = generate_diagnosis(
                    findings=result.findings,
                    topology=result.topology_snapshot,
                    score=result.score,
                    history=result.trend,
                )
                diagnosis_json = json.dumps(diagnosis.to_dict(), default=str)
                self._job_repo.update_status(job_id, progress=90)

                # Phase 5: Store findings
                log_fn(f"Storing {len(result.findings)} findings...")
                mark_phase("findings")
                finding_dicts = []
                for f in result.findings:
                    evidence_data = [
                        {
                            "source_file": e.source_file,
                            "line_number": e.line_number,
                            "excerpt": e.excerpt,
                            "command": e.command,
                        }
                        for e in (f.evidence or [])
                    ]
                    finding_dicts.append(
                        {
                            "rule_id": getattr(f, "id", None)
                            or getattr(f, "rule_id", None)
                            or "unknown",
                            "category": getattr(f, "category", None),
                            "component": getattr(f, "component", None),
                            "severity": f.severity.value
                            if hasattr(f.severity, "value")
                            else str(f.severity),
                            "title": f.condition,
                            "description": f.cause,
                            "evidence_json": json.dumps(evidence_data, default=str),
                            "recommendation": f.treatment,
                            "evidence_ref": (
                                evidence_data[0]["source_file"] if evidence_data else None
                            ),
                        }
                    )
                self._finding_repo.bulk_insert(job_id, finding_dicts)
                stored_findings = self._finding_repo.get_by_job_id(job_id)
                record_scan_lifecycle_events(
                    server_id=server_id,
                    job_id=job_id,
                    findings=stored_findings,
                )

                # Phase 5.5: Store correlations (synthesized findings)
                if diagnosis.correlations:
                    log_fn(f"Storing {len(diagnosis.correlations)} synthesized findings...")
                    correlation_records = []
                    for c in diagnosis.correlations:
                        correlation_records.append(
                            {
                                "correlation_id": c.correlation_id,
                                "severity": c.severity,
                                "root_cause_hypothesis": c.root_cause_hypothesis,
                                "blast_radius": c.blast_radius,
                                "supporting_rule_ids": list(
                                    c.supporting_rule_ids or []
                                ),
                                "fix_bundle": c.fix_bundle,
                                "confidence": c.confidence,
                            }
                        )
                    self._correlation_repo.bulk_insert(job_id, correlation_records)

                self._job_repo.update_status(job_id, progress=95)

                # Phase 6: Update job as success
                summary = f"{len(result.findings)} findings, score {result.score}/100"
                from dataclasses import asdict
                model_dict = (
                    asdict(model)
                    if hasattr(model, "__dataclass_fields__")
                    else {}
                )
                model_json = json.dumps(model_dict, default=str)
                self._job_repo.update_status(
                    job_id,
                    "success",
                    score=result.score,
                    summary=summary,
                    diagnosis_json=diagnosis_json,
                    raw_report_path=report_path,
                    model_json=model_json,
                    progress=100,
                )
                mark_phase("done", "success")
                self._log_repo.append(job_id, f"Scan complete: {summary}")

        except JobCancelledError as e:
            if active_phase_key:
                mark_phase(active_phase_key, "cancelled", str(e))
            self._job_repo.update_status(job_id, "cancelled", summary=str(e), error_message=str(e))
            self._log_repo.append(job_id, f"Cancelled: {str(e)}")
        except JobTimeoutError as e:
            if active_phase_key:
                mark_phase(active_phase_key, "failed", str(e))
            self._job_repo.update_status(
                job_id,
                "failed",
                summary="Timed out",
                error_message=str(e),
            )
            self._log_repo.append(job_id, f"Timeout: {str(e)}")
        except Exception as e:
            error_msg = f"Scan failed: {str(e)}"
            tb = traceback.format_exc()
            if active_phase_key:
                mark_phase(active_phase_key, "failed", str(e))
            self._job_repo.update_status(job_id, "failed", summary=error_msg, error_message=tb)
            self._log_repo.append(job_id, error_msg)
            # Log traceback for debugging (truncated)
            self._log_repo.append(job_id, f"Traceback: {tb[:500]}")

    def _generate_report(
        self,
        job_id: int,
        model: Any,
        result: Any,
        log_fn: Any,
    ) -> str:
        """Generate HTML report and return the file path."""
        from server_doctor.actions.html_report import HTMLReportAction

        report_dir = _REPORTS_DIR / str(job_id)
        report_dir.mkdir(parents=True, exist_ok=True)
        report_path = report_dir / "report.html"

        reporter = HTMLReportAction()
        reporter.generate(
            model,
            result.findings,
            output_path=str(report_path),
            ws_inventory=result.ws_inventory,
            trend=result.trend,
            suppressed_findings=result.suppressed_findings,
            waiver_source=result.waiver_source,
        )

        return str(report_path)

    @staticmethod
    def _now() -> str:
        from datetime import datetime, timezone

        return datetime.now(timezone.utc).isoformat()

    @staticmethod
    def _initial_phases() -> list[dict[str, Any]]:
        return [
            {
                "key": key,
                "label": label,
                "status": "pending",
                "progress": progress,
                "started_at": None,
                "finished_at": None,
                "error": None,
            }
            for key, label, progress in SCAN_PHASES
        ]

    def _progress_to_phase(
        self,
        job_id: int,
        phases: list[dict[str, Any]],
        pct: int,
    ) -> None:
        if pct >= 75:
            key = "runtime"
        elif pct >= 60:
            key = "security"
        elif pct >= 45:
            key = "apps"
        elif pct >= 30:
            key = "nginx"
        else:
            key = "os_services"
        now = self._now()
        for phase in phases:
            if phase["key"] == key:
                if phase["status"] == "pending":
                    phase["status"] = "running"
                    phase["started_at"] = now
                break
        self._job_repo.update_status(
            job_id,
            progress=max(0, min(100, int(pct))),
            phases_json=json.dumps(phases, default=str),
        )

    def shutdown(self, wait: bool = True) -> None:
        """Shutdown the thread pool."""
        self._executor.shutdown(wait=wait)


# Global singleton (initialized by app.py)
scan_job_runner: ScanJobRunner | None = None


def get_runner() -> ScanJobRunner:
    """Get the global ScanJobRunner instance."""
    global scan_job_runner
    if scan_job_runner is None:
        scan_job_runner = ScanJobRunner()
    return scan_job_runner
