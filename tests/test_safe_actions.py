from fastapi.testclient import TestClient

from server_doctor.connector.ssh import CommandResult
from server_doctor.engine.actions import SafeActionRequest, build_safe_action_response
from server_doctor.storage.db import init_db, set_db_path
from server_doctor.storage.repositories import ServerRepository
from server_doctor.web.app import create_app
from tests.web_auth_helpers import csrf_headers, login


class FakeSSH:
    def run(self, command):
        return CommandResult(command, "LISTEN 127.0.0.1:3000\n", "", 0)


def test_preview_nginx_test_returns_command_without_running():
    response = build_safe_action_response(
        SafeActionRequest(server_id=1, action_id="nginx_test", mode="preview")
    )

    assert response.command == "sudo nginx -t"
    assert response.output is None


def test_list_open_ports_run_uses_mocked_ssh():
    response = build_safe_action_response(
        SafeActionRequest(server_id=1, action_id="list_open_ports", mode="run"),
        ssh=FakeSSH(),
    )

    assert "LISTEN" in response.output


def test_unknown_action_raises_key_error():
    try:
        build_safe_action_response(SafeActionRequest(server_id=1, action_id="shell"))
    except KeyError:
        return
    raise AssertionError("unknown action should raise")


def test_action_route_requires_auth(tmp_path, monkeypatch):
    monkeypatch.setenv("SERVER_DOCTOR_WEB_PASSWORD", "pw")
    set_db_path(tmp_path / "actions.db")
    init_db()
    ServerRepository().create("web", "127.0.0.1")
    client = TestClient(create_app())

    response = client.post(
        "/api/actions/safe",
        json={"server_id": 1, "action_id": "nginx_test"},
    )

    assert response.status_code == 401

    csrf = login(client, "pw")
    response = client.post(
        "/api/actions/safe",
        json={"server_id": 1, "action_id": "nginx_test"},
        headers=csrf_headers(csrf),
    )
    assert response.status_code == 200
