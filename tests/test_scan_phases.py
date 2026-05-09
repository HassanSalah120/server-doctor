import json

from server_doctor.storage.db import init_db, set_db_path
from server_doctor.storage.repositories import ScanJobRepository, ServerRepository


def test_old_job_without_phases_returns_empty_list(tmp_path):
    set_db_path(tmp_path / "old-phases.db")
    init_db()
    server_id = ServerRepository().create("web", "127.0.0.1")
    job_id = ScanJobRepository().create(server_id)

    job = ScanJobRepository().get_by_id(job_id)

    assert job is not None
    assert job.to_dict()["phases"] == []


def test_successful_job_can_store_done_phase(tmp_path):
    set_db_path(tmp_path / "phases.db")
    init_db()
    server_id = ServerRepository().create("web", "127.0.0.1")
    job_id = ScanJobRepository().create(server_id)
    phases = [
        {
            "key": "done",
            "label": "Done",
            "status": "success",
            "progress": 100,
            "started_at": "now",
            "finished_at": "now",
            "error": None,
        }
    ]

    ScanJobRepository().update_status(job_id, "success", phases_json=json.dumps(phases))

    job = ScanJobRepository().get_by_id(job_id)

    assert job is not None
    assert job.to_dict()["phases"][-1]["key"] == "done"
    assert job.to_dict()["phases"][-1]["progress"] == 100
