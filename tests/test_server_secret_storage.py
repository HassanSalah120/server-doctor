import pytest
from fastapi.testclient import TestClient

from server_doctor.storage.db import get_db, init_db, set_db_path
from server_doctor.storage.repositories import ServerRepository
from server_doctor.web.app import create_app
from tests.web_auth_helpers import csrf_headers, login


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("SERVER_DOCTOR_WEB_PASSWORD", "test-password")
    set_db_path(tmp_path / "secrets.db")
    init_db()
    return TestClient(create_app())


def test_create_server_password_uses_secret_ref_not_plaintext(client, monkeypatch):
    stored: dict[str, str] = {}

    def fake_store(name, host, password):
        stored["password"] = password
        return f"{name}:{host}:ref"

    monkeypatch.setattr("server_doctor.web.routes.servers.store_server_password", fake_store)
    monkeypatch.setattr(
        "server_doctor.web.routes.servers.get_server_password",
        lambda ref: stored["password"],
    )

    csrf = login(client)
    response = client.post(
        "/api/servers",
        json={"name": "web1", "host": "127.0.0.1", "password": "secret"},
        headers=csrf_headers(csrf),
    )

    assert response.status_code == 200
    server_id = response.json()["server"]["id"]
    row = get_db().execute("SELECT * FROM servers WHERE id = ?", (server_id,)).fetchone()
    assert row["password"] is None
    assert row["password_secret_ref"] == "web1:127.0.0.1:ref"
    assert row["password_storage"] == "keyring"


def test_create_server_key_passphrase_uses_secret_ref(client, monkeypatch):
    stored: dict[str, str] = {}

    def fake_store(name, host, passphrase):
        stored["passphrase"] = passphrase
        return f"key:{name}:{host}:ref"

    monkeypatch.setattr(
        "server_doctor.web.routes.servers.store_server_key_passphrase",
        fake_store,
    )
    monkeypatch.setattr(
        "server_doctor.web.routes.servers.get_server_key_passphrase",
        lambda ref: stored["passphrase"],
    )

    csrf = login(client)
    response = client.post(
        "/api/servers",
        json={
            "name": "web1",
            "host": "127.0.0.1",
            "key_path": "~/.ssh/id_ed25519",
            "key_passphrase": "key-secret",
        },
        headers=csrf_headers(csrf),
    )

    assert response.status_code == 200
    server_id = response.json()["server"]["id"]
    row = get_db().execute("SELECT * FROM servers WHERE id = ?", (server_id,)).fetchone()
    assert "key-secret" not in dict(row).values()
    assert row["key_passphrase_secret_ref"] == "key:web1:127.0.0.1:ref"
    assert row["key_passphrase_storage"] == "keyring"
    assert response.json()["server"]["key_passphrase"] is True


def test_keyring_failure_blocks_plaintext_persistence(client, monkeypatch):
    def fail_store(name, host, password):
        from server_doctor.web.secrets import SecretStorageError

        raise SecretStorageError("keyring unavailable")

    monkeypatch.setattr("server_doctor.web.routes.servers.store_server_password", fail_store)

    csrf = login(client)
    response = client.post(
        "/api/servers",
        json={"name": "web1", "host": "127.0.0.1", "password": "secret"},
        headers=csrf_headers(csrf),
    )

    assert response.status_code == 500
    rows = get_db().execute("SELECT * FROM servers").fetchall()
    assert rows == []


def test_key_passphrase_keyring_failure_blocks_persistence(client, monkeypatch):
    def fail_store(name, host, passphrase):
        from server_doctor.web.secrets import SecretStorageError

        raise SecretStorageError("keyring unavailable")

    monkeypatch.setattr(
        "server_doctor.web.routes.servers.store_server_key_passphrase",
        fail_store,
    )

    csrf = login(client)
    response = client.post(
        "/api/servers",
        json={
            "name": "web1",
            "host": "127.0.0.1",
            "key_path": "~/.ssh/id_ed25519",
            "key_passphrase": "secret",
        },
        headers=csrf_headers(csrf),
    )

    assert response.status_code == 500
    rows = get_db().execute("SELECT * FROM servers").fetchall()
    assert rows == []


def test_legacy_plaintext_row_remains_readable(tmp_path):
    set_db_path(tmp_path / "legacy.db")
    init_db()
    repo = ServerRepository()
    server_id = repo.create("legacy", "127.0.0.1", password="old-secret")

    server = repo.get_by_id(server_id)

    assert server is not None
    assert server.password == "old-secret"
    assert server.password_secret_ref is None


def test_delete_server_deletes_secret_ref(client, monkeypatch):
    deleted: list[str] = []

    monkeypatch.setattr(
        "server_doctor.web.routes.servers.store_server_password",
        lambda name, host, password: "secret-ref",
    )
    monkeypatch.setattr(
        "server_doctor.web.routes.servers.get_server_password",
        lambda ref: "secret",
    )
    monkeypatch.setattr(
        "server_doctor.web.routes.servers.delete_server_password",
        lambda ref: deleted.append(ref),
    )

    csrf = login(client)
    create = client.post(
        "/api/servers",
        json={"name": "web1", "host": "127.0.0.1", "password": "secret"},
        headers=csrf_headers(csrf),
    )
    server_id = create.json()["server"]["id"]

    response = client.delete(f"/api/servers/{server_id}", headers=csrf_headers(csrf))

    assert response.status_code == 200
    assert deleted == ["secret-ref"]


def test_delete_server_deletes_key_passphrase_ref(client, monkeypatch):
    deleted: list[str] = []

    monkeypatch.setattr(
        "server_doctor.web.routes.servers.store_server_key_passphrase",
        lambda name, host, passphrase: "key-secret-ref",
    )
    monkeypatch.setattr(
        "server_doctor.web.routes.servers.get_server_key_passphrase",
        lambda ref: "secret",
    )
    monkeypatch.setattr(
        "server_doctor.web.routes.servers.delete_server_key_passphrase",
        lambda ref: deleted.append(ref),
    )

    csrf = login(client)
    create = client.post(
        "/api/servers",
        json={
            "name": "web1",
            "host": "127.0.0.1",
            "key_path": "~/.ssh/id_ed25519",
            "key_passphrase": "secret",
        },
        headers=csrf_headers(csrf),
    )
    server_id = create.json()["server"]["id"]

    response = client.delete(f"/api/servers/{server_id}", headers=csrf_headers(csrf))

    assert response.status_code == 200
    assert deleted == ["key-secret-ref"]
