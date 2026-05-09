from server_doctor.connector.ssh import CommandResult
from server_doctor.scanner.backup_readiness import BackupReadinessScanner


class FakeSSH:
    def run(self, command):
        return CommandResult(command, "/usr/bin/restic\n", "", 0)


def test_backup_readiness_scanner_detects_tools():
    model = BackupReadinessScanner(FakeSSH()).scan()

    assert model.tools_detected == ["/usr/bin/restic"]
