import json

from fastapi.testclient import TestClient

from server_doctor.engine.finding_fingerprint import fingerprint_record
from server_doctor.engine.readiness import build_readiness
from server_doctor.storage.db import init_db, set_db_path
from server_doctor.storage.models import FindingRecord
from server_doctor.storage.repositories import (
    AcceptedRiskRepository,
    FindingRepository,
    LifecycleEventRepository,
    ScanJobRepository,
    ServerRepository,
)
from server_doctor.web.app import create_app
from tests.web_auth_helpers import login


def test_regressed_critical_finding_is_readiness_blocker():
    finding = FindingRecord(
        id=1,
        job_id=10,
        rule_id="CUSTOM-LOW",
        severity="critical",
        title="Critical issue came back",
    )

    readiness = build_readiness(
        10,
        [finding],
        regression_by_finding={1: {"is_regression": True}},
    )

    assert readiness.ready is False
    assert readiness.blockers == ["Regression: Critical issue came back"]


def test_accepted_risk_prevents_regression_blocker(tmp_path, monkeypatch):
    monkeypatch.setenv("SERVER_DOCTOR_WEB_PASSWORD", "pw")
    set_db_path(tmp_path / "readiness-regression.db")
    init_db()
    server_id = ServerRepository().create("web", "127.0.0.1")
    old_job_id = ScanJobRepository().create(server_id)
    new_job_id = ScanJobRepository().create(server_id)
    ScanJobRepository().update_status(new_job_id, "success")
    evidence_json = json.dumps([{"excerpt": "https://example.com/.env => HTTP 200"}])
    FindingRepository().bulk_insert(
        old_job_id,
        [
            {
                "rule_id": "HTTP-PROBE-005",
                "severity": "critical",
                "title": "Sensitive path exposed",
                "evidence_json": evidence_json,
            }
        ],
    )
    old_finding = FindingRepository().get_by_job_id(old_job_id)[0]
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
    FindingRepository().bulk_insert(
        new_job_id,
        [
            {
                "rule_id": "HTTP-PROBE-005",
                "severity": "critical",
                "title": "Sensitive path exposed",
                "evidence_json": evidence_json,
            }
        ],
    )
    AcceptedRiskRepository().create(
        server_id=server_id,
        rule_id="HTTP-PROBE-005",
        finding_title="Sensitive path exposed",
        reason="Intentional test exposure",
    )
    client = TestClient(create_app())
    login(client, "pw")

    response = client.get(f"/api/readiness/{new_job_id}")

    assert response.status_code == 200
    assert response.json()["ready"] is True
