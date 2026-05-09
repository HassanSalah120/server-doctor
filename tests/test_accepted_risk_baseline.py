import pytest
from fastapi.testclient import TestClient

from server_doctor.storage.db import init_db, set_db_path
from server_doctor.storage.repositories import (
    AcceptedRiskRepository,
    FindingRepository,
    ScanJobRepository,
    ServerRepository,
)
from server_doctor.web.app import create_app
from tests.web_auth_helpers import csrf_headers, login


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("SERVER_DOCTOR_WEB_PASSWORD", "pw")
    set_db_path(tmp_path / "baseline.db")
    init_db()
    return TestClient(create_app())


def _job_with_blocker() -> tuple[int, int, int]:
    server_id = ServerRepository().create("web", "127.0.0.1")
    job_id = ScanJobRepository().create(server_id)
    ScanJobRepository().update_status(job_id, "success")
    FindingRepository().bulk_insert(
        job_id,
        [
            {
                "rule_id": "HTTP-PROBE-007",
                "severity": "critical",
                "title": "HTTPS 502",
            }
        ],
    )
    finding_id = FindingRepository().get_by_job_id(job_id)[0].id
    return server_id, job_id, finding_id


def test_accept_risk_requires_reason(client):
    _server_id, _job_id, finding_id = _job_with_blocker()
    token = login(client, "pw")

    response = client.post(
        "/api/baseline/accept",
        json={"finding_id": finding_id, "reason": ""},
        headers=csrf_headers(token),
    )

    assert response.status_code == 400


def test_accept_risk_records_baseline_decision(client):
    server_id, _job_id, finding_id = _job_with_blocker()
    token = login(client, "pw")

    response = client.post(
        "/api/baseline/accept",
        json={"finding_id": finding_id, "reason": "Intentional maintenance window"},
        headers=csrf_headers(token),
    )

    assert response.status_code == 200
    assert response.json()["rule_id"] == "HTTP-PROBE-007"
    assert AcceptedRiskRepository().get_by_server_id(server_id)


def test_readiness_ignores_accepted_blocker(client):
    _server_id, job_id, finding_id = _job_with_blocker()
    token = login(client, "pw")
    client.post(
        "/api/baseline/accept",
        json={"finding_id": finding_id, "reason": "Accepted temporarily"},
        headers=csrf_headers(token),
    )

    response = client.get(f"/api/readiness/{job_id}")

    assert response.status_code == 200
    body = response.json()
    assert body["ready"] is True
    assert body["accepted_risks"][0]["rule_id"] == "HTTP-PROBE-007"
