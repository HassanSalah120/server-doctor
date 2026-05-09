from server_doctor.connector.ssh import CommandResult
from server_doctor.scanner.redis_deep import RedisDeepScanner


class FakeSSH:
    def run(self, command):
        return CommandResult(command, "active\n", "", 0)


def test_redis_deep_scanner_records_service_state():
    model = RedisDeepScanner(FakeSSH()).scan()

    assert model.service_state == "active"
