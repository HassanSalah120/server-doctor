from server_doctor.analyzer.backup_readiness_auditor import BackupReadinessAuditor
from server_doctor.model.server import BackupArtifact, BackupReadinessModel, ServerModel


def test_production_app_without_backup_evidence_emits():
    model = ServerModel(
        hostname="host",
        backup_readiness=BackupReadinessModel(enabled=True, production_indicators=True),
    )

    findings = BackupReadinessAuditor(model).audit()

    assert any(f.id == "BACKUP-READY-002" for f in findings)


def test_recent_app_and_db_backup_avoid_missing_backup_findings():
    model = ServerModel(
        hostname="host",
        backup_readiness=BackupReadinessModel(
            enabled=True,
            production_indicators=True,
            tools_detected=["restic"],
            app_backups=[BackupArtifact(path="/backups/app.tar.gz", age_days=1, size_bytes=2048)],
            db_backups=[BackupArtifact(path="/backups/db.sql.gz", age_days=1, size_bytes=2048)],
            restore_test_evidence=["restore-test-2026-05-01"],
        ),
    )

    findings = BackupReadinessAuditor(model).audit()

    assert not any(f.id in {"BACKUP-READY-002", "BACKUP-READY-003"} for f in findings)


def test_permission_denied_emits_capability_note_only():
    model = ServerModel(
        hostname="host",
        backup_readiness=BackupReadinessModel(
            enabled=True,
            production_indicators=True,
            permission_denied=True,
        ),
    )

    findings = BackupReadinessAuditor(model).audit()

    assert [f.id for f in findings] == ["BACKUP-READY-CAPABILITY"]
