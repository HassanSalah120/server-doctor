import json

import pytest
from fastapi.testclient import TestClient

from server_doctor.storage.db import init_db, set_db_path
from server_doctor.storage.repositories import ScanJobRepository, ServerRepository
from server_doctor.web.app import create_app
from tests.web_auth_helpers import login


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("SERVER_DOCTOR_WEB_PASSWORD", "test-password")
    set_db_path(tmp_path / "compare.db")
    init_db()
    return TestClient(create_app())


def test_compare_without_previous_scan_returns_empty(client):
    login(client)
    server_id = ServerRepository().create("web", "127.0.0.1")
    job_id = ScanJobRepository().create(server_id)

    response = client.get(f"/api/reports/{job_id}/compare")

    assert response.status_code == 200
    assert response.json()["previous_job_id"] is None
    assert response.json()["drift"] == []


def test_compare_detects_new_public_port(client):
    login(client)
    server_id = ServerRepository().create("web", "127.0.0.1")
    previous = ScanJobRepository().create(server_id)
    current = ScanJobRepository().create(server_id)
    ScanJobRepository().update_status(
        previous,
        "success",
        model_json=json.dumps({"network_surface": {"endpoints": []}}),
    )
    ScanJobRepository().update_status(
        current,
        "success",
        model_json=json.dumps(
            {
                "network_surface": {
                    "endpoints": [
                        {"protocol": "tcp", "port": 6379, "is_public": True}
                    ]
                }
            }
        ),
    )

    response = client.get(f"/api/reports/{current}/compare")

    assert response.status_code == 200
    assert response.json()["previous_job_id"] == previous
    assert response.json()["drift"][0]["after"] == "tcp/6379"
