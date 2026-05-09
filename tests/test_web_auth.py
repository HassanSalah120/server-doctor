import pytest
from fastapi.testclient import TestClient

from server_doctor.storage.db import init_db, set_db_path
from server_doctor.web.app import create_app, validate_web_bind


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("SERVER_DOCTOR_WEB_PASSWORD", "test-password")
    set_db_path(tmp_path / "auth.db")
    init_db()
    return TestClient(create_app())


def test_login_success_returns_csrf(client):
    response = client.post("/api/auth/login", json={"password": "test-password"})

    assert response.status_code == 200
    body = response.json()
    assert body["authenticated"] is True
    assert body["csrf_token"]


def test_login_wrong_password_returns_401(client):
    response = client.post("/api/auth/login", json={"password": "wrong"})

    assert response.status_code == 401


def test_scan_without_cookie_returns_401(client):
    response = client.post("/api/scan", json={"server_id": 1})

    assert response.status_code == 401


def test_scan_with_cookie_without_csrf_returns_403(client):
    login = client.post("/api/auth/login", json={"password": "test-password"})
    assert login.status_code == 200

    response = client.post("/api/scan", json={"server_id": 1})

    assert response.status_code == 403


def test_public_bind_requires_override(monkeypatch):
    monkeypatch.delenv("SERVER_DOCTOR_ALLOW_PUBLIC_BIND", raising=False)
    with pytest.raises(RuntimeError):
        validate_web_bind("0.0.0.0")

    monkeypatch.setenv("SERVER_DOCTOR_ALLOW_PUBLIC_BIND", "1")
    validate_web_bind("0.0.0.0")
