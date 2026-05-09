from server_doctor.connector.ssh import CommandResult
from server_doctor.scanner.node_runtime import NodeRuntimeScanner


class FakeSSH:
    def run(self, command):
        if command.startswith("ps"):
            return CommandResult(command, "123 app node node server.js\n", "", 0)
        return CommandResult(command, "LISTEN 0 128 127.0.0.1:3000 0.0.0.0:*\n", "", 0)


def test_node_runtime_scanner_collects_processes_and_listeners():
    model = NodeRuntimeScanner(FakeSSH()).scan()

    assert model.processes[0].pid == 123
    assert model.listeners[0].port == 3000
