import json

import pytest
from fastapi.testclient import TestClient

from server_doctor.connector.ssh import CommandResult
from server_doctor.engine.fix_validation import build_validation_plan, evaluate_validation
from server_doctor.storage.db import init_db, set_db_path
from server_doctor.storage.models import FindingRecord
from server_doctor.storage.repositories import (
    FindingRepository,
    FixAttemptRepository,
    ScanJobRepository,
    ServerRepository,
)
from server_doctor.web.app import create_app
from tests.web_auth_helpers import csrf_headers, login


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("SERVER_DOCTOR_WEB_PASSWORD", "pw")
    set_db_path(tmp_path / "validation.db")
    init_db()
    return TestClient(create_app())


def _finding(rule_id: str = "HTTP-PROBE-005") -> int:
    server_id = ServerRepository().create("web", "127.0.0.1")
    job_id = ScanJobRepository().create(server_id)
    ScanJobRepository().update_status(job_id, "success")
    FindingRepository().bulk_insert(
        job_id,
        [
            {
                "rule_id": rule_id,
                "severity": "critical",
                "title": "composer.json exposed",
                "evidence_json": json.dumps(
                    [
                        {
                            "excerpt": "https://example.com/composer.json => HTTP 200",
                            "command": "curl -I https://example.com/composer.json",
                        }
                    ]
                ),
                "recommendation": "Block the path.",
            }
        ],
    )
    return FindingRepository().get_by_job_id(job_id)[0].id


def _stored_finding() -> FindingRecord:
    return FindingRecord(
        id=1,
        job_id=1,
        rule_id="HTTP-PROBE-005",
        severity="critical",
        title="composer.json exposed",
        evidence_json=json.dumps(
            [
                {
                    "excerpt": "https://example.com/composer.json => HTTP 200",
                    "command": "curl -I https://example.com/composer.json",
                }
            ]
        ),
    )


def test_sensitive_path_validation_plan_expects_blocked_status():
    finding = _stored_finding()

    plan = build_validation_plan(finding)

    assert plan.can_validate is True
    assert "curl" in plan.command
    assert "403 or 404" in plan.expected


def test_sensitive_path_validation_marks_resolved_on_404():
    finding = _stored_finding()

    result = evaluate_validation(finding, stdout="404", exit_code=0)

    assert result.status == "resolved"


def test_validate_preview_requires_auth(client):
    response = client.post("/api/fixes/validate", json={"finding_id": 1})

    assert response.status_code == 401


def test_validate_run_stores_attempt(client, monkeypatch):
    finding_id = _finding()

    class FakeSSH:
        def __init__(self, config):
            self.config = config

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return False

        def run(self, command):
            return CommandResult(command=command, stdout="404", stderr="", exit_code=0)

    monkeypatch.setattr("server_doctor.web.routes.fixes.SSHConnector", FakeSSH)
    token = login(client, "pw")

    response = client.post(
        "/api/fixes/validate",
        json={"finding_id": finding_id, "mode": "run"},
        headers=csrf_headers(token),
    )

    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "resolved"
    assert body["attempt_id"]
    attempts = FixAttemptRepository().get_by_finding_id(finding_id)
    assert attempts[0].status == "resolved"
