from server_doctor.storage.db import init_db, set_db_path
from server_doctor.storage.repositories import (
    LifecycleEventRepository,
    ScanJobRepository,
    ServerRepository,
)


def test_lifecycle_events_round_trip(tmp_path):
    set_db_path(tmp_path / "lifecycle.db")
    init_db()
    server_id = ServerRepository().create("web", "127.0.0.1")
    job_id = ScanJobRepository().create(server_id)

    event_id = LifecycleEventRepository().create(
        server_id=server_id,
        job_id=job_id,
        finding_fingerprint="abc",
        rule_id="HTTP-PROBE-005",
        target="https://example.com/.env",
        event_type="detected",
        source="scan",
        details={"status": "seen"},
    )

    events = LifecycleEventRepository().get_by_fingerprint(server_id, "abc")
    assert events[0].id == event_id
    assert events[0].target == "https://example.com/.env"
    assert '"status": "seen"' in events[0].details_json


def test_duplicate_detected_event_for_same_job_is_idempotent(tmp_path):
    set_db_path(tmp_path / "lifecycle-idempotent.db")
    init_db()
    server_id = ServerRepository().create("web", "127.0.0.1")
    job_id = ScanJobRepository().create(server_id)
    repo = LifecycleEventRepository()

    first = repo.create(
        server_id=server_id,
        job_id=job_id,
        finding_fingerprint="abc",
        rule_id="HTTP-PROBE-005",
        event_type="detected",
        source="scan",
        idempotent=True,
    )
    second = repo.create(
        server_id=server_id,
        job_id=job_id,
        finding_fingerprint="abc",
        rule_id="HTTP-PROBE-005",
        event_type="detected",
        source="scan",
        idempotent=True,
    )

    assert first == second
    assert len(repo.get_by_fingerprint(server_id, "abc")) == 1
