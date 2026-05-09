from server_doctor.connector.ssh import CommandResult
from server_doctor.scanner.mysql_deep import MySQLDeepScanner


class FakeSSH:
    def run(self, command):
        if "bind-address" in command:
            return CommandResult(command, "bind-address = 0.0.0.0", "", 0)
        return CommandResult(command, "active\n", "", 0)


def test_mysql_deep_scanner_parses_bind_address():
    model = MySQLDeepScanner(FakeSSH()).scan()

    assert model.bind_addresses == ["0.0.0.0"]
