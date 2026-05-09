import json

import pytest
from fastapi.testclient import TestClient

from server_doctor.connector.ssh import CommandResult
from server_doctor.storage.db import init_db, set_db_path
from server_doctor.storage.repositories import (
    FindingRepository,
    LifecycleEventRepository,
    ScanJobRepository,
    ServerRepository,
)
from server_doctor.web.app import create_app
from tests.web_auth_helpers import csrf_headers, login


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("SERVER_DOCTOR_WEB_PASSWORD", "pw")
    set_db_path(tmp_path / "fix-validation-lifecycle.db")
    init_db()
    return TestClient(create_app())


def _finding() -> tuple[int, int]:
    server_id = ServerRepository().create("web", "127.0.0.1")
    job_id = ScanJobRepository().create(server_id)
    FindingRepository().bulk_insert(
        job_id,
        [
            {
                "rule_id": "HTTP-PROBE-005",
                "severity": "critical",
                "title": "Sensitive path exposed",
                "evidence_json": json.dumps(
                    [{"excerpt": "https://example.com/composer.json => HTTP 200"}]
                ),
            }
        ],
    )
    return server_id, FindingRepository().get_by_job_id(job_id)[0].id


def _fake_ssh(monkeypatch, stdout: str):
    class FakeSSH:
        def __init__(self, config):
            self.config = config

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return False

        def run(self, command):
            return CommandResult(command=command, stdout=stdout, stderr="", exit_code=0)

    monkeypatch.setattr("server_doctor.web.routes.fixes.SSHConnector", FakeSSH)


def test_successful_validation_creates_resolved_lifecycle_event(client, monkeypatch):
    server_id, finding_id = _finding()
    _fake_ssh(monkeypatch, "404")
    token = login(client, "pw")

    response = client.post(
        "/api/fixes/validate",
        json={"finding_id": finding_id, "mode": "run"},
        headers=csrf_headers(token),
    )

    assert response.status_code == 200
    events = LifecycleEventRepository().get_by_server_id(server_id)
    assert events[0].event_type == "validated_resolved"
    assert "expected" in events[0].details_json
    assert "404" in events[0].details_json


def test_failed_validation_creates_validation_failed_lifecycle_event(client, monkeypatch):
    server_id, finding_id = _finding()
    _fake_ssh(monkeypatch, "200")
    token = login(client, "pw")

    response = client.post(
        "/api/fixes/validate",
        json={"finding_id": finding_id, "mode": "run"},
        headers=csrf_headers(token),
    )

    assert response.status_code == 200
    events = LifecycleEventRepository().get_by_server_id(server_id)
    assert events[0].event_type == "validation_failed"
    assert "200" in events[0].details_json
