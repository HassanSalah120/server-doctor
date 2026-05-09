"""Laravel runtime diagnosis."""

from __future__ import annotations

from server_doctor.model.evidence import Evidence, Severity
from server_doctor.model.finding import Finding
from server_doctor.model.server import LaravelRuntimeProject, ServerModel


class LaravelRuntimeAuditor:
    def __init__(self, model: ServerModel) -> None:
        self.model = model

    def audit(self) -> list[Finding]:
        findings: list[Finding] = []
        for project in self.model.laravel_runtime.projects:
            if not project.env_readable:
                findings.append(_finding(
                    "LARAVEL-RUNTIME-CAPABILITY",
                    Severity.INFO,
                    "Laravel .env could not be read",
                    "Runtime checks that depend on .env were skipped.",
                    project,
                    "read .env: permission denied or unavailable",
                ))
                continue
            queue = _env(project, "QUEUE_CONNECTION")
            if (
                queue
                and queue.lower() not in {"sync", "null"}
                and project.queue_worker_running is False
            ):
                findings.append(_finding(
                    "LARAVEL-RUNTIME-001",
                    Severity.CRITICAL,
                    "Laravel queue worker is missing",
                    f"QUEUE_CONNECTION uses {queue}, but no worker process was detected.",
                    project,
                    "QUEUE_CONNECTION=<redacted>",
                ))
            if project.scheduler_detected is False and _has_schedule_signal(project):
                findings.append(_finding(
                    "LARAVEL-RUNTIME-002",
                    Severity.WARNING,
                    "Laravel scheduler is missing",
                    "Scheduled commands appear configured but no schedule runner was detected.",
                    project,
                    "php artisan schedule:run not found",
                ))
            if project.failed_jobs_count and project.failed_jobs_count > 0:
                findings.append(_finding(
                    "LARAVEL-RUNTIME-003",
                    Severity.WARNING,
                    "Laravel failed jobs are present",
                    f"{project.failed_jobs_count} failed job row(s) were observed.",
                    project,
                    f"failed_jobs={project.failed_jobs_count}",
                ))
            if project.horizon_installed and project.horizon_running is False:
                findings.append(_finding(
                    "LARAVEL-RUNTIME-004",
                    Severity.WARNING,
                    "Horizon is installed but not running",
                    "Horizon was detected but no active Horizon process was observed.",
                    project,
                    "horizon process missing",
                ))
            if project.recent_critical_log_lines:
                findings.append(_finding(
                    "LARAVEL-RUNTIME-006",
                    Severity.CRITICAL,
                    "Recent Laravel critical errors found",
                    "Laravel log contains recent critical/emergency/error entries.",
                    project,
                    project.recent_critical_log_lines[0][:300],
                ))
            if project.storage_writable is False:
                findings.append(_finding(
                    "LARAVEL-RUNTIME-007",
                    Severity.CRITICAL,
                    "Laravel storage is not writable",
                    "storage/ is not writable by the application.",
                    project,
                    "storage writable=false",
                ))
            if project.cache_writable is False:
                findings.append(_finding(
                    "LARAVEL-RUNTIME-008",
                    Severity.CRITICAL,
                    "Laravel bootstrap/cache is not writable",
                    "bootstrap/cache/ is not writable by the application.",
                    project,
                    "bootstrap/cache writable=false",
                ))
            if project.public_storage_symlink is False:
                findings.append(_finding(
                    "LARAVEL-RUNTIME-009",
                    Severity.WARNING,
                    "Laravel public/storage symlink is missing",
                    "public/storage is not a symlink.",
                    project,
                    "public/storage symlink=false",
                ))
            if _env(project, "APP_KEY") in {None, ""}:
                findings.append(_finding(
                    "LARAVEL-RUNTIME-011",
                    Severity.CRITICAL,
                    "Laravel APP_KEY is missing",
                    "APP_KEY is absent or empty in the environment.",
                    project,
                    "APP_KEY=<missing>",
                ))
            if _redis_required(project) and _redis_unavailable(self.model):
                findings.append(_finding(
                    "LARAVEL-RUNTIME-012",
                    Severity.WARNING,
                    "Laravel Redis dependency is unavailable",
                    "The app references Redis, but Redis availability is unknown or failed.",
                    project,
                    "REDIS dependency referenced",
                ))
        return findings


def env_evidence(project: LaravelRuntimeProject, key: str, value: str | None) -> Evidence:
    shown = "<missing>" if value is None else "<redacted>"
    return Evidence(
        source_file=project.env_path or f"{project.path}/.env",
        line_number=0,
        excerpt=f"{key}={shown}",
    )


def _finding(rule_id, severity, condition, cause, project, excerpt) -> Finding:
    return Finding(
        id=rule_id,
        severity=severity,
        confidence=0.88,
        condition=condition,
        cause=cause,
        evidence=[Evidence(project.env_path or project.path, 0, excerpt)],
        treatment="Review Laravel runtime configuration and process supervision.",
        impact=["Application jobs, sessions, or runtime behavior may fail."],
    )


def _env(project: LaravelRuntimeProject, key: str) -> str | None:
    return project.env.get(key.upper())


def _has_schedule_signal(project: LaravelRuntimeProject) -> bool:
    return project.env.get("SCHEDULE_ENABLED") in {"1", "true", "yes"}


def _redis_required(project: LaravelRuntimeProject) -> bool:
    keys = ("CACHE_DRIVER", "CACHE_STORE", "QUEUE_CONNECTION", "SESSION_DRIVER")
    return any((_env(project, key) or "").lower() == "redis" for key in keys)


def _redis_unavailable(model: ServerModel) -> bool:
    state = getattr(model.redis_deep, "service_state", None)
    return state in {"failed", "stopped", "unavailable"} or (
        model.redis_deep.enabled and not model.redis_deep.instances
    )
