"""High-value Laravel production checks."""

from __future__ import annotations

import re
from dataclasses import dataclass

from server_doctor.checks import BaseCheck, CheckContext, register_check
from server_doctor.model.evidence import Evidence, Severity
from server_doctor.model.finding import Finding

APP_DEBUG_RE = re.compile(r"^\s*APP_DEBUG\s*=\s*(true|1|yes)\s*$", re.I | re.M)
APP_ENV_RE = re.compile(r"^\s*APP_ENV\s*=\s*([^\s#]+)", re.I | re.M)
QUEUE_CONNECTION_RE = re.compile(r"^\s*QUEUE_CONNECTION\s*=\s*([^\s#]+)", re.I | re.M)


@dataclass
class LaravelProject:
    path: str
    env_path: str
    env_text: str | None = None


def redact_env_line(line: str) -> str:
    key = line.split("=", 1)[0].strip()
    return f"{key}=<redacted>"


@register_check
class LaravelProductionAuditor(BaseCheck):
    @property
    def category(self) -> str:
        return "laravel"

    @property
    def requires_ssh(self) -> bool:
        return False

    def run(self, context: CheckContext) -> list[Finding]:
        findings: list[Finding] = []
        for project in self._projects(context):
            findings.extend(self.audit_project(project))
        return findings

    def audit_project(self, project: LaravelProject) -> list[Finding]:
        findings: list[Finding] = []
        if project.env_text is None:
            return findings
        debug = APP_DEBUG_RE.search(project.env_text)
        if debug:
            findings.append(
                Finding(
                    id="LARAVEL-PROD-001",
                    severity=Severity.CRITICAL,
                    confidence=0.95,
                    condition="Laravel APP_DEBUG is enabled in production posture",
                    cause="APP_DEBUG exposes stack traces and sensitive runtime configuration.",
                    evidence=[
                        Evidence(
                            source_file=project.env_path,
                            line_number=1,
                            excerpt=redact_env_line(debug.group(0)),
                            command="read Laravel .env APP_DEBUG",
                        )
                    ],
                    treatment="Set APP_DEBUG=false and clear cached config.",
                    impact=["Sensitive debug output may be exposed to users."],
                )
            )
        env = APP_ENV_RE.search(project.env_text)
        if env and env.group(1).strip().strip("\"'").lower() != "production":
            findings.append(
                Finding(
                    id="LARAVEL-PROD-002",
                    severity=Severity.WARNING,
                    confidence=0.9,
                    condition="Laravel APP_ENV is not production",
                    cause="The application environment does not indicate production.",
                    evidence=[
                        Evidence(
                            source_file=project.env_path,
                            line_number=1,
                            excerpt=redact_env_line(env.group(0)),
                            command="read Laravel .env APP_ENV",
                        )
                    ],
                    treatment="Set APP_ENV=production and refresh cached configuration.",
                    impact=["Production-only hardening and caching behavior may be disabled."],
                )
            )
        return findings

    def _projects(self, context: CheckContext) -> list[LaravelProject]:
        projects: list[LaravelProject] = []
        for project in getattr(context.model, "projects", []) or []:
            ptype = getattr(getattr(project, "type", None), "value", getattr(project, "type", ""))
            if str(ptype).lower() != "laravel":
                continue
            path = getattr(project, "path", "")
            if not path:
                continue
            env_path = f"{path.rstrip('/')}/.env"
            env_text = None
            if context.ssh and context.ssh.file_exists(env_path):
                env_text = context.ssh.read_file(env_path)
            projects.append(LaravelProject(path=path, env_path=env_path, env_text=env_text))
        return projects
