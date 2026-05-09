import json

from server_doctor.engine.finding_fingerprint import fingerprint_record
from server_doctor.engine.regression import is_regression, record_scan_lifecycle_events
from server_doctor.storage.db import init_db, set_db_path
from server_doctor.storage.repositories import (
    AcceptedRiskRepository,
    FindingRepository,
    LifecycleEventRepository,
    ScanJobRepository,
    ServerRepository,
)


def _setup(tmp_path):
    set_db_path(tmp_path / "regression.db")
    init_db()
    server_id = ServerRepository().create("web", "127.0.0.1")
    return server_id


def _insert_finding(server_id: int, job_id: int):
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
    return FindingRepository().get_by_job_id(job_id)[0]


def test_resolved_old_finding_seen_again_becomes_regression(tmp_path):
    server_id = _setup(tmp_path)
    old_job_id = ScanJobRepository().create(server_id)
    old_finding = _insert_finding(server_id, old_job_id)
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
    current = _insert_finding(server_id, new_job_id)

    record_scan_lifecycle_events(
        server_id=server_id,
        job_id=new_job_id,
        findings=[current],
    )

    events = LifecycleEventRepository().get_by_fingerprint(server_id, fingerprint)
    assert any(event.event_type == "regression" for event in events)


def test_active_accepted_risk_does_not_become_regression(tmp_path):
    server_id = _setup(tmp_path)
    old_job_id = ScanJobRepository().create(server_id)
    old_finding = _insert_finding(server_id, old_job_id)
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
    AcceptedRiskRepository().create(
        server_id=server_id,
        rule_id=old_finding.rule_id,
        finding_title=old_finding.title,
        reason="Intentional exposure in test",
    )
    new_job_id = ScanJobRepository().create(server_id)
    current = _insert_finding(server_id, new_job_id)

    record_scan_lifecycle_events(
        server_id=server_id,
        job_id=new_job_id,
        findings=[current],
    )

    events = LifecycleEventRepository().get_by_fingerprint(server_id, fingerprint)
    assert not any(event.event_type == "regression" for event in events)


def test_same_job_validation_does_not_create_regression(tmp_path):
    server_id = _setup(tmp_path)
    job_id = ScanJobRepository().create(server_id)
    finding = _insert_finding(server_id, job_id)
    fingerprint, target = fingerprint_record(server_id, finding)
    LifecycleEventRepository().create(
        server_id=server_id,
        job_id=job_id,
        finding_fingerprint=fingerprint,
        rule_id=finding.rule_id,
        target=target,
        event_type="validated_resolved",
        source="test",
    )

    events = LifecycleEventRepository().get_by_fingerprint(server_id, fingerprint)

    assert is_regression(events, job_id, accepted_active=False) is False
