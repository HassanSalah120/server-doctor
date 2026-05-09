import json

import pytest
from fastapi.testclient import TestClient

from server_doctor.connector.ssh import CommandResult
from server_doctor.storage.db import init_db, set_db_path
from server_doctor.storage.repositories import (
    FindingRepository,
    FixAttemptRepository,
    LifecycleEventRepository,
    ScanJobRepository,
    ServerRepository,
)
from server_doctor.web.app import create_app
from tests.web_auth_helpers import csrf_headers, login

NGINX_CONF = """
server {
    listen 443 ssl;
    server_name vote.schmobinquiz.de;

    location / {
        try_files $uri /index.html;
    }
}
""".strip()


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("SERVER_DOCTOR_WEB_PASSWORD", "pw")
    set_db_path(tmp_path / "safe-apply.db")
    init_db()
    return TestClient(create_app())


def _finding(
    rule_id: str = "HTTP-PROBE-SOFT404",
    url: str = "https://vote.schmobinquiz.de/composer.json",
) -> int:
    server_id = ServerRepository().create("Votes Production", "127.0.0.1")
    job_id = ScanJobRepository().create(server_id)
    model_json = json.dumps(
        {
            "nginx": {
                "servers": [
                    {
                        "server_names": ["vote.schmobinquiz.de"],
                        "source_file": "/etc/nginx/sites-enabled/vote.conf",
                    }
                ]
            }
        }
    )
    ScanJobRepository().update_status(job_id, "success", model_json=model_json)
    FindingRepository().bulk_insert(
        job_id,
        [
            {
                "rule_id": rule_id,
                "severity": "warning",
                "title": "Sensitive path returns SPA fallback with HTTP 200",
                "evidence_json": json.dumps(
                    [
                        {
                            "excerpt": f"{url} => HTTP 200",
                            "command": f"curl -I {url}",
                        }
                    ]
                ),
            }
        ],
    )
    return FindingRepository().get_by_job_id(job_id)[0].id


class FakeSSH:
    commands: list[str] = []
    outputs: list[CommandResult] = []
    content = NGINX_CONF

    def __init__(self, config):
        self.config = config

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False

    def read_file(self, path):
        self.commands.append(f"read:{path}")
        return self.content

    def run(self, command):
        self.commands.append(command)
        if self.outputs:
            return self.outputs.pop(0)
        return CommandResult(command=command, stdout="", stderr="", exit_code=0)


def _ok(command: str = "ok", stdout: str = "") -> CommandResult:
    return CommandResult(command=command, stdout=stdout, stderr="", exit_code=0)


def _fail(command: str = "fail", stderr: str = "failed") -> CommandResult:
    return CommandResult(command=command, stdout="", stderr=stderr, exit_code=1)


def test_sensitive_path_apply_preview_returns_patch(client, monkeypatch):
    finding_id = _finding()
    FakeSSH.commands = []
    FakeSSH.outputs = []
    monkeypatch.setattr("server_doctor.web.routes.fixes.SSHConnector", FakeSSH)
    token = login(client, "pw")

    response = client.post(
        "/api/fixes/safe-apply/sensitive-path",
        json={"finding_id": finding_id, "mode": "preview"},
        headers=csrf_headers(token),
    )

    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "preview"
    assert "SAFE-APPLY-001" in body["patch_preview"]
    assert body["nginx_file"] == "/etc/nginx/sites-enabled/vote.conf"
    assert FakeSSH.commands == ["read:/etc/nginx/sites-enabled/vote.conf"]


def test_sensitive_path_apply_requires_typed_confirmation(client, monkeypatch):
    finding_id = _finding()
    FakeSSH.commands = []
    FakeSSH.outputs = []
    monkeypatch.setattr("server_doctor.web.routes.fixes.SSHConnector", FakeSSH)
    token = login(client, "pw")

    response = client.post(
        "/api/fixes/safe-apply/sensitive-path",
        json={"finding_id": finding_id, "mode": "apply", "confirmation": "APPLY"},
        headers=csrf_headers(token),
    )

    assert response.status_code == 400


def test_sensitive_path_apply_success_records_lifecycle(client, monkeypatch):
    finding_id = _finding()
    FakeSSH.commands = []
    FakeSSH.outputs = [
        _ok("mkdir"),
        _ok("backup"),
        _ok("write"),
        _ok("move"),
        _ok("nginx-test"),
        _ok("reload"),
        _ok("curl", "404"),
    ]
    monkeypatch.setattr("server_doctor.web.routes.fixes.SSHConnector", FakeSSH)
    token = login(client, "pw")

    response = client.post(
        "/api/fixes/safe-apply/sensitive-path",
        json={
            "finding_id": finding_id,
            "mode": "apply",
            "confirmation": "APPLY SAFE NGINX BLOCK",
            "ack_backup": True,
            "ack_risk": True,
        },
        headers=csrf_headers(token),
    )

    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "resolved"
    assert body["observed"] == "404"
    assert body["rollback_performed"] is False
    attempts = FixAttemptRepository().get_by_finding_id(finding_id)
    assert attempts[0].action == "safe_apply_sensitive_path"
    events = LifecycleEventRepository().get_by_server_id(attempts[0].server_id)
    assert events[-1].event_type == "validated_resolved"


def test_sensitive_path_apply_rolls_back_on_nginx_test_failure(client, monkeypatch):
    finding_id = _finding()
    FakeSSH.commands = []
    FakeSSH.outputs = [
        _ok("mkdir"),
        _ok("backup"),
        _ok("write"),
        _ok("move"),
        _fail("nginx-test", "syntax error"),
        _ok("rollback"),
        _ok("rollback-test"),
        _ok("rollback-reload"),
    ]
    monkeypatch.setattr("server_doctor.web.routes.fixes.SSHConnector", FakeSSH)
    token = login(client, "pw")

    response = client.post(
        "/api/fixes/safe-apply/sensitive-path",
        json={
            "finding_id": finding_id,
            "mode": "apply",
            "confirmation": "APPLY SAFE NGINX BLOCK",
            "ack_backup": True,
            "ack_risk": True,
        },
        headers=csrf_headers(token),
    )

    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "error"
    assert body["rollback_performed"] is True
    assert "syntax error" in body["error"]
    assert not any(command == "systemctl reload nginx" for command in FakeSSH.commands[:7])


def test_sensitive_path_apply_rolls_back_when_validation_observes_200(client, monkeypatch):
    finding_id = _finding()
    FakeSSH.commands = []
    FakeSSH.outputs = [
        _ok("mkdir"),
        _ok("backup"),
        _ok("write"),
        _ok("move"),
        _ok("nginx-test"),
        _ok("reload"),
        _ok("curl", "200"),
        _ok("rollback"),
        _ok("rollback-test"),
        _ok("rollback-reload"),
    ]
    monkeypatch.setattr("server_doctor.web.routes.fixes.SSHConnector", FakeSSH)
    token = login(client, "pw")

    response = client.post(
        "/api/fixes/safe-apply/sensitive-path",
        json={
            "finding_id": finding_id,
            "mode": "apply",
            "confirmation": "APPLY SAFE NGINX BLOCK",
            "ack_backup": True,
            "ack_risk": True,
        },
        headers=csrf_headers(token),
    )

    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "still_failing"
    assert body["observed"] == "200"
    assert body["rollback_performed"] is True


def test_sensitive_path_apply_rejects_unknown_sensitive_target(client, monkeypatch):
    finding_id = _finding("API-001", "https://vote.schmobinquiz.de/admin")
    monkeypatch.setattr("server_doctor.web.routes.fixes.SSHConnector", FakeSSH)
    token = login(client, "pw")

    response = client.post(
        "/api/fixes/safe-apply/sensitive-path",
        json={"finding_id": finding_id, "mode": "preview"},
        headers=csrf_headers(token),
    )

    assert response.status_code == 200
    assert response.json()["status"] == "not_applicable"
