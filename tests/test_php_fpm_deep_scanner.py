from server_doctor.connector.ssh import CommandResult
from server_doctor.scanner.php_fpm_deep import PhpFpmDeepScanner


class FakeSSH:
    def run(self, command):
        if command.startswith("test -S"):
            return CommandResult(command, "", "", 1)
        return CommandResult(command, "", "", 0)


def test_php_fpm_deep_scanner_records_socket_existence():
    model = PhpFpmDeepScanner(FakeSSH()).scan(["/run/php/missing.sock"])

    assert model.enabled is True
    assert model.socket_exists["/run/php/missing.sock"] is False
