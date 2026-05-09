from server_doctor.connector.ssh import CommandResult
from server_doctor.model.server import ProjectInfo, ProjectType
from server_doctor.scanner.laravel_runtime import LaravelRuntimeScanner, parse_env


def test_parse_env_reads_queue_connection():
    assert parse_env("QUEUE_CONNECTION=redis\nAPP_KEY=base64:x")["QUEUE_CONNECTION"] == "redis"


class FakeSSH:
    def run(self, command):
        if "cat" in command:
            return CommandResult(command, "QUEUE_CONNECTION=sync\nAPP_KEY=base64:x", "", 0)
        return CommandResult(command, "", "", 0)


def test_laravel_runtime_scanner_reads_laravel_project_env():
    project = ProjectInfo(path="/var/www/app", type=ProjectType.LARAVEL, confidence=1)

    model = LaravelRuntimeScanner(FakeSSH()).scan([project])

    assert model.projects[0].env["QUEUE_CONNECTION"] == "sync"
