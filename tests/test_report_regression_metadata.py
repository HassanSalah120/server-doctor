import json

from fastapi.testclient import TestClient

from server_doctor.engine.finding_fingerprint import fingerprint_record
from server_doctor.storage.db import init_db, set_db_path
from server_doctor.storage.repositories import (
    FindingRepository,
    LifecycleEventRepository,
    ScanJobRepository,
    ServerRepository,
)
from server_doctor.web.app import create_app
from tests.web_auth_helpers import login


def _insert_finding(job_id: int):
    FindingRepository().bulk_insert(
        job_id,
        [
            {
                "rule_id": "HTTP-PROBE-005",
                "severity": "critical",
                "title": "Sensitive path exposed",
                "evidence_json": json.dumps(
                    [{"excerpt": "https://example.com/.env => HTTP 200"}]
                ),
            }
        ],
    )
    return FindingRepository().get_by_job_id(job_id)[0]


def test_report_marks_reappeared_validated_finding_as_regression(tmp_path, monkeypatch):
    monkeypatch.setenv("SERVER_DOCTOR_WEB_PASSWORD", "pw")
    set_db_path(tmp_path / "report-regression.db")
    init_db()
    server_id = ServerRepository().create("web", "127.0.0.1")
    old_job_id = ScanJobRepository().create(server_id)
    old_finding = _insert_finding(old_job_id)
    fingerprint, target = fingerprint_record(server_id, old_finding)
    LifecycleEventRepository().create(
        server_id=server_id,
        job_id=old_job_id,
        finding_fingerprint=fingerprint,
        rule_id=old_finding.rule_id,
        target=target,
        event_type="validated_resolved",
        source="test",
    )
    new_job_id = ScanJobRepository().create(server_id)
    ScanJobRepository().update_status(new_job_id, "success")
    current = _insert_finding(new_job_id)
    LifecycleEventRepository().create(
        server_id=server_id,
        job_id=new_job_id,
        finding_fingerprint=fingerprint,
        rule_id=current.rule_id,
        target=target,
        event_type="regression",
        source="test",
    )
    client = TestClient(create_app())
    login(client, "pw")

    response = client.get(f"/api/reports/{new_job_id}")

    assert response.status_code == 200
    finding = response.json()["normalized_findings"][0]
    assert finding["is_regression"] is True
    assert finding["resolved_in_job_id"] == old_job_id
    assert finding["regressed_in_job_id"] == new_job_id
