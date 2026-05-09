"""Read-only Laravel runtime scanner."""

from __future__ import annotations

import re

from server_doctor.model.server import LaravelRuntimeModel, LaravelRuntimeProject, ProjectInfo

ENV_LINE_RE = re.compile(r"^\s*([A-Z0-9_]+)\s*=\s*(.*)\s*$", re.M)


class LaravelRuntimeScanner:
    def __init__(self, ssh) -> None:
        self.ssh = ssh

    def scan(self, projects: list[ProjectInfo] | None = None) -> LaravelRuntimeModel:
        runtime = LaravelRuntimeModel(enabled=True)
        for project in projects or []:
            if str(project.type.value) != "laravel":
                continue
            env_path = getattr(project, "env_path", None) or f"{project.path.rstrip('/')}/.env"
            env_result = self.ssh.run(f"sudo test -r {env_path} && sudo cat {env_path}")
            env_readable = env_result.exit_code == 0
            env = parse_env(env_result.stdout if env_readable else "")
            proc_command = (
                "ps -eo pid,command | grep -E 'queue:work|horizon|octane' "
                "| grep -v grep || true"
            )
            proc = self.ssh.run(proc_command).stdout
            failed_command = (
                f"cd {project.path} && "
                "php artisan queue:failed --no-ansi 2>/dev/null || true"
            )
            failed = self.ssh.run(failed_command).stdout
            schedule_command = "crontab -l 2>/dev/null | grep 'schedule:run' || true"
            storage_command = f"test -L {project.path}/public/storage"
            runtime.projects.append(
                LaravelRuntimeProject(
                    path=project.path,
                    env_path=env_path,
                    env=env,
                    queue_worker_running="queue:work" in proc or "horizon" in proc,
                    scheduler_detected=_safe_bool(self.ssh.run(schedule_command).stdout),
                    failed_jobs_count=_count_failed_jobs(failed),
                    horizon_installed="horizon" in proc.lower(),
                    horizon_running="horizon" in proc.lower(),
                    octane_installed="octane" in proc.lower(),
                    octane_running="octane" in proc.lower(),
                    public_storage_symlink=self.ssh.run(storage_command).exit_code == 0,
                    env_readable=env_readable,
                )
            )
        return runtime


def parse_env(text: str) -> dict[str, str | None]:
    values: dict[str, str | None] = {}
    for match in ENV_LINE_RE.finditer(text or ""):
        value = match.group(2).strip().strip('"').strip("'")
        values[match.group(1).upper()] = value
    return values


def _count_failed_jobs(text: str) -> int | None:
    rows = [line for line in (text or "").splitlines() if line.strip()]
    if not rows:
        return 0
    return max(0, len(rows) - 1)


def _safe_bool(text: str) -> bool:
    return bool((text or "").strip())
