"""Backup posture checks."""

from __future__ import annotations

from server_doctor.checks import BaseCheck, CheckContext, register_check
from server_doctor.model.evidence import Evidence, Severity
from server_doctor.model.finding import Finding


@register_check
class BackupAuditor(BaseCheck):
    @property
    def category(self) -> str:
        return "ops"

    @property
    def requires_ssh(self) -> bool:
        return False

    def run(self, context: CheckContext) -> list[Finding]:
        posture = getattr(context.model, "ops_posture", None)
        if posture is None or not hasattr(posture, "backup_tools_detected"):
            return []
        tools = getattr(posture, "backup_tools_detected", None) or []
        if tools:
            return []
        return [
            Finding(
                id="BACKUP-001",
                severity=Severity.INFO,
                confidence=0.7,
                condition="No backup tool detected",
                cause=(
                    "The operations posture scan did not detect a known backup tool."
                ),
                evidence=[
                    Evidence(
                        "ops_posture",
                        0,
                        "backup_tools_detected=[]",
                        "ops posture scan",
                    )
                ],
                treatment="Configure and monitor off-server backups.",
                impact=["Recovery may depend on unverified manual backups."],
            )
        ]
