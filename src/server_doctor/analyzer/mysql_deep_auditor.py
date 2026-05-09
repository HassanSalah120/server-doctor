"""MySQL/MariaDB deep diagnosis."""

from __future__ import annotations

import re

from server_doctor.model.evidence import Evidence, Severity
from server_doctor.model.finding import Finding
from server_doctor.model.server import ServerModel

PUBLIC_BIND_RE = re.compile(r"^(0\.0\.0\.0|::|\*)$")


class MySQLDeepAuditor:
    def __init__(self, model: ServerModel) -> None:
        self.model = model

    def audit(self) -> list[Finding]:
        data = self.model.mysql_deep
        if data.installed is False:
            return []
        findings: list[Finding] = []
        for bind in data.bind_addresses:
            if PUBLIC_BIND_RE.match(bind):
                findings.append(_finding(
                    "MYSQL-DEEP-001",
                    Severity.CRITICAL,
                    "MySQL bind address is public",
                    f"MySQL bind-address is {bind}.",
                    f"bind-address={bind}",
                    "mysql config scan",
                ))
        if data.root_remote_login is True:
            findings.append(_finding(
                "MYSQL-DEEP-002",
                Severity.CRITICAL,
                "MySQL root remote login is allowed",
                "mysql.user indicates root can connect remotely.",
                "user=root host=%",
                "SELECT user,host FROM mysql.user",
            ))
        if data.anonymous_users is True:
            findings.append(_finding(
                "MYSQL-DEEP-003",
                Severity.WARNING,
                "Anonymous MySQL users exist",
                "mysql.user includes anonymous user rows.",
                "user='' found",
                "SELECT user,host FROM mysql.user",
            ))
        if data.service_state in {"failed", "inactive", "stopped"}:
            if _docker_mysql_running(self.model):
                pass
            else:
                severity = Severity.CRITICAL if _app_requires_mysql(self.model) else Severity.WARNING
                findings.append(_finding(
                    "MYSQL-DEEP-011",
                    severity,
                    "MySQL service is not healthy",
                    f"MySQL service state is {data.service_state}.",
                    f"service_state={data.service_state}",
                    "systemctl is-active mysql mariadb",
                ))
        return findings


def _docker_mysql_running(model: ServerModel) -> bool:
    if model.nginx is None or model.nginx.mode != "DOCKER":
        return False
    for container in model.services.docker_containers:
        if container.status.startswith("Up") or container.status == "running":
            name_lower = container.name.lower()
            image_lower = container.image.lower()
            if "mysql" in name_lower or "mariadb" in name_lower or "mysql" in image_lower or "mariadb" in image_lower:
                return True
    return False


def _app_requires_mysql(model: ServerModel) -> bool:
    for project in model.laravel_runtime.projects:
        db_connection = (project.env.get("DB_CONNECTION") or "").lower()
        if db_connection in {"mysql", "mariadb"}:
            return True
    return False


def _finding(rule_id, severity, condition, cause, excerpt, command) -> Finding:
    return Finding(
        id=rule_id,
        severity=severity,
        confidence=0.9,
        condition=condition,
        cause=cause,
        evidence=[Evidence("mysql diagnosis", 0, excerpt, command)],
        treatment="Review MySQL configuration, accounts, and service health.",
        impact=["Database security or availability may be at risk."],
    )
