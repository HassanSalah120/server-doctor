from types import SimpleNamespace

from server_doctor.checks import CheckContext
from server_doctor.checks.ops.backup_auditor import BackupAuditor
from server_doctor.model.server import ServerModel


def test_no_backup_tool_detected_emits_info():
    model = ServerModel(hostname="web")
    model.ops_posture = SimpleNamespace(backup_tools_detected=[])

    findings = BackupAuditor().run(CheckContext(model=model))

    assert [f.id for f in findings] == ["BACKUP-001"]


def test_backup_capability_unavailable_does_not_emit_false_critical():
    model = ServerModel(hostname="web")

    assert BackupAuditor().run(CheckContext(model=model)) == []
