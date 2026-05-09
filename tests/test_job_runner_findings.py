from server_doctor.storage.db import init_db, set_db_path
from server_doctor.storage.repositories import FindingRepository, ScanJobRepository, ServerRepository


def test_finding_id_value_is_stored_as_rule_id(tmp_path):
    set_db_path(tmp_path / "findings.db")
    init_db()
    server_id = ServerRepository().create("web", "127.0.0.1")
    job_id = ScanJobRepository().create(server_id)

    FindingRepository().bulk_insert(
        job_id,
        [{"rule_id": "NGX-SEC-2", "severity": "warning", "title": "Header missing"}],
    )

    findings = FindingRepository().get_by_job_id(job_id)
    assert findings[0].rule_id == "NGX-SEC-2"


def test_unknown_rule_id_fallback_does_not_crash(tmp_path):
    set_db_path(tmp_path / "unknown-findings.db")
    init_db()
    server_id = ServerRepository().create("web", "127.0.0.1")
    job_id = ScanJobRepository().create(server_id)

    FindingRepository().bulk_insert(job_id, [{"severity": "info", "title": "Unknown"}])

    findings = FindingRepository().get_by_job_id(job_id)
    assert findings[0].rule_id == "unknown"
