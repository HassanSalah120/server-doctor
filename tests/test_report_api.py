import json

import pytest
from fastapi.testclient import TestClient

from server_doctor.storage.db import init_db, set_db_path
from server_doctor.storage.repositories import (
    FindingRepository,
    ScanJobRepository,
    ServerRepository,
)
from server_doctor.web.app import create_app
from tests.web_auth_helpers import login


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("SERVER_DOCTOR_WEB_PASSWORD", "test-password")
    set_db_path(tmp_path / "report.db")
    init_db()
    return TestClient(create_app())


def _job_with_findings(findings):
    server_id = ServerRepository().create("web", "127.0.0.1")
    job_id = ScanJobRepository().create(server_id)
    ScanJobRepository().update_status(job_id, "success", model_json=json.dumps({"hostname": "web"}))
    FindingRepository().bulk_insert(job_id, findings)
    return job_id


def test_report_returns_sorted_normalized_findings(client):
    login(client)
    job_id = _job_with_findings(
        [
            {"rule_id": "INFO-1", "severity": "info", "title": "Info"},
            {
                "rule_id": "NGX-SEC-2",
                "severity": "warning",
                "title": "Security",
                "evidence_json": json.dumps([{"source_file": "/etc/nginx/site"}]),
            },
        ]
    )

    response = client.get(f"/api/reports/{job_id}")

    assert response.status_code == 200
    normalized = response.json()["normalized_findings"]
    assert normalized[0]["rule_id"] == "NGX-SEC-2"
    assert normalized[0]["fix_priority"] > normalized[1]["fix_priority"]


def test_malformed_evidence_json_returns_empty_evidence(client):
    login(client)
    job_id = _job_with_findings(
        [{"rule_id": "BAD", "severity": "warning", "title": "Bad", "evidence_json": "{"}]
    )

    response = client.get(f"/api/reports/{job_id}")

    assert response.status_code == 200
    finding = response.json()["normalized_findings"][0]
    assert finding["evidence"] == []
    assert finding["evidence_warning"] == "Malformed evidence JSON"


def test_empty_findings_returns_valid_report(client):
    login(client)
    job_id = _job_with_findings([])

    response = client.get(f"/api/reports/{job_id}")

    assert response.status_code == 200
    assert response.json()["findings"] == []
    assert response.json()["normalized_findings"] == []
