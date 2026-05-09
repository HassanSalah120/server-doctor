import pytest
from fastapi.testclient import TestClient

from server_doctor.web.app import create_app
from server_doctor.storage.db import set_db_path, init_db
from server_doctor.storage.repositories import ScanJobRepository
from tests.web_auth_helpers import csrf_headers, login


@pytest.fixture
def client(tmp_path, monkeypatch):
    # use an isolated sqlite file for each test run
    monkeypatch.setenv("SERVER_DOCTOR_WEB_PASSWORD", "test-password")
    dbfile = tmp_path / "test.db"
    set_db_path(str(dbfile))
    init_db()
    app = create_app()
    return TestClient(app)


def test_create_list_and_delete_server(client):
    csrf = login(client)
    # create
    res = client.post("/api/servers", json={
        "name": "web1",
        "host": "127.0.0.1",
    }, headers=csrf_headers(csrf))
    assert res.status_code == 200
    sid = res.json()["server"]["id"]

    # list
    res = client.get("/api/servers")
    assert res.status_code == 200
    assert len(res.json()["servers"]) == 1

    # delete success
    res = client.delete(f"/api/servers/{sid}", headers=csrf_headers(csrf))
    assert res.status_code == 200
    assert res.json()["deleted"] is True

    # now gone
    res = client.get(f"/api/servers/{sid}")
    assert res.status_code == 404


def test_delete_server_with_jobs(client):
    csrf = login(client)
    # create server and a job referencing it
    res = client.post("/api/servers", json={
        "name": "web2",
        "host": "127.0.0.1",
    }, headers=csrf_headers(csrf))
    assert res.status_code == 200
    sid = res.json()["server"]["id"]

    ScanJobRepository().create(sid)

    # attempt delete should fail with 400
    res = client.delete(f"/api/servers/{sid}", headers=csrf_headers(csrf))
    assert res.status_code == 400
    assert "scan jobs" in res.json().get("detail", "").lower()

    # server still present
    res = client.get(f"/api/servers/{sid}")
    assert res.status_code == 200


def test_delete_server_with_jobs_cascade(client):
    csrf = login(client)
    # create server and a job referencing it
    res = client.post("/api/servers", json={
        "name": "web3",
        "host": "127.0.0.1",
    }, headers=csrf_headers(csrf))
    assert res.status_code == 200
    sid = res.json()["server"]["id"]

    job_id = ScanJobRepository().create(sid)
    # add a dummy finding and log for the job
    from server_doctor.storage.repositories import FindingRepository, JobLogRepository
    FindingRepository().bulk_insert(sid, [{
        "rule_id": "TEST",
        "severity": "info",
        "title": "dummy",
    }])
    JobLogRepository().append(job_id, "log message")

    # ensure job was created
    jobs_before = ScanJobRepository().get_by_server_id(sid)
    assert len(jobs_before) == 1

    # delete with cascade
    res = client.delete(f"/api/servers/{sid}?cascade=true", headers=csrf_headers(csrf))
    assert res.status_code == 200
    body = res.json()
    assert body["deleted"] is True
    assert body.get("jobs_deleted", 0) == 1

    # server, jobs, and children gone
    res = client.get(f"/api/servers/{sid}")
    assert res.status_code == 404
    jobs = ScanJobRepository().get_by_server_id(sid)
    assert jobs == []
    # ensure no findings/logs left
    assert FindingRepository().get_by_job_id(job_id) == []
    assert JobLogRepository().get_by_job_id(job_id) == []
