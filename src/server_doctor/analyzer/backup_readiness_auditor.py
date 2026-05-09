"""Backup and restore-readiness diagnosis."""

from __future__ import annotations

from server_doctor.model.evidence import Evidence, Severity
from server_doctor.model.finding import Finding
from server_doctor.model.server import ServerModel


class BackupReadinessAuditor:
    def __init__(self, model: ServerModel) -> None:
        self.model = model

    def audit(self) -> list[Finding]:
        data = self.model.backup_readiness
        if data.permission_denied:
            return [_finding(
                "BACKUP-READY-CAPABILITY",
                Severity.INFO,
                "Backup evidence could not be fully inspected",
                "Permission denied prevented backup readiness checks.",
                "permission_denied=true",
            )]
        if not data.production_indicators:
            return []
        findings: list[Finding] = []
        if not data.tools_detected:
            findings.append(_finding(
                "BACKUP-READY-001",
                Severity.WARNING,
                "No backup tool detected",
                "No known backup tool was detected on a production-like server.",
                "tools_detected=[]",
            ))
        if not data.app_backups:
            findings.append(_finding(
                "BACKUP-READY-002",
                Severity.CRITICAL,
                "No recent app backup evidence",
                "No application backup artifact was observed.",
                "app_backups=[]",
            ))
        if not data.db_backups:
            findings.append(_finding(
                "BACKUP-READY-003",
                Severity.CRITICAL,
                "No recent database backup evidence",
                "No database backup artifact was observed.",
                "db_backups=[]",
            ))
        for artifact in [*data.app_backups, *data.db_backups]:
            if artifact.age_days is not None and artifact.age_days > 7:
                findings.append(_finding(
                    "BACKUP-READY-006",
                    Severity.WARNING,
                    "Backup is too old",
                    f"{artifact.path} is {artifact.age_days:.1f} day(s) old.",
                    artifact.path,
                ))
            if artifact.size_bytes is not None and artifact.size_bytes < 1024:
                findings.append(_finding(
                    "BACKUP-READY-007",
                    Severity.WARNING,
                    "Backup artifact is suspiciously small",
                    f"{artifact.path} is only {artifact.size_bytes} bytes.",
                    artifact.path,
                ))
        if not data.restore_test_evidence:
            findings.append(_finding(
                "BACKUP-READY-008",
                Severity.WARNING,
                "No restore test evidence",
                "No recent restore-test marker or log was observed.",
                "restore_test_evidence=[]",
            ))
        return findings


def _finding(rule_id, severity, condition, cause, excerpt) -> Finding:
    return Finding(
        id=rule_id,
        severity=severity,
        confidence=0.8,
        condition=condition,
        cause=cause,
        evidence=[Evidence("backup readiness", 0, excerpt, "backup readiness scan")],
        treatment="Configure monitored off-server backups and periodic restore tests.",
        impact=["Recovery may be impossible or unverified."],
    )
