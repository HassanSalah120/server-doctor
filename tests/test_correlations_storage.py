from server_doctor.storage.db import init_db, set_db_path
from server_doctor.storage.repositories import CorrelationRepository, ScanJobRepository, ServerRepository


def test_correlation_supporting_rule_ids_reads_back_array(tmp_path):
    set_db_path(tmp_path / "correlations.db")
    init_db()
    server_id = ServerRepository().create("web", "127.0.0.1")
    job_id = ScanJobRepository().create(server_id)

    CorrelationRepository().bulk_insert(
        job_id,
        [
            {
                "correlation_id": "C1",
                "supporting_rule_ids": ["A", "B"],
            }
        ],
    )

    rows = CorrelationRepository().get_by_job_id(job_id)

    assert rows[0].supporting_rule_ids == ["A", "B"]
    assert rows[0].to_dict()["supporting_rule_ids"] == ["A", "B"]


def test_legacy_comma_correlation_supporting_ids_are_compatible(tmp_path):
    set_db_path(tmp_path / "legacy-correlations.db")
    init_db()
    server_id = ServerRepository().create("web", "127.0.0.1")
    job_id = ScanJobRepository().create(server_id)

    from server_doctor.storage.db import get_db

    get_db().execute(
        """INSERT INTO correlations (job_id, correlation_id, supporting_rule_ids)
           VALUES (?, ?, ?)""",
        (job_id, "C1", "A,B"),
    )
    get_db().commit()

    rows = CorrelationRepository().get_by_job_id(job_id)

    assert rows[0].supporting_rule_ids == ["A", "B"]
