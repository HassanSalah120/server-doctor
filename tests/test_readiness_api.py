from fastapi.testclient import TestClient

from server_doctor.storage.db import init_db, set_db_path
from server_doctor.storage.repositories import (
    FindingRepository,
    ScanJobRepository,
    ServerRepository,
)
from server_doctor.web.app import create_app
from tests.web_auth_helpers import login


def test_readiness_api_returns_blockers(tmp_path, monkeypatch):
    monkeypatch.setenv("SERVER_DOCTOR_WEB_PASSWORD", "pw")
    set_db_path(tmp_path / "readiness.db")
    init_db()
    server_id = ServerRepository().create("web", "127.0.0.1")
    job_id = ScanJobRepository().create(server_id)
    ScanJobRepository().update_status(job_id, "success")
    FindingRepository().bulk_insert(
        job_id,
        [{"rule_id": "HTTP-PROBE-007", "severity": "critical", "title": "HTTPS 502"}],
    )
    client = TestClient(create_app())
    login(client, "pw")

    response = client.get(f"/api/readiness/{job_id}")

    assert response.status_code == 200
    assert response.json()["ready"] is False


def test_readiness_api_no_scan_returns_404(tmp_path, monkeypatch):
    monkeypatch.setenv("SERVER_DOCTOR_WEB_PASSWORD", "pw")
    set_db_path(tmp_path / "readiness-empty.db")
    init_db()
    client = TestClient(create_app())
    login(client, "pw")

    response = client.get("/api/readiness/999")

    assert response.status_code == 404
