import pytest
from fastapi.testclient import TestClient

from server_doctor.storage.db import init_db, set_db_path
from server_doctor.storage.repositories import (
    FindingRepository,
    ScanJobRepository,
    ServerRepository,
)
from server_doctor.web.app import create_app
from tests.web_auth_helpers import login


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("SERVER_DOCTOR_WEB_PASSWORD", "test-password")
    set_db_path(tmp_path / "fixes.db")
    init_db()
    return TestClient(create_app())


def _job_with_finding(rule_id: str):
    server_id = ServerRepository().create("web", "127.0.0.1")
    job_id = ScanJobRepository().create(server_id)
    FindingRepository().bulk_insert(
        job_id,
        [
            {
                "rule_id": rule_id,
                "severity": "warning",
                "title": "Finding",
                "evidence_ref": "/etc/nginx/site",
            }
        ],
    )
    return job_id


def _job_with_finding_payload(rule_id: str, payload: dict):
    server_id = ServerRepository().create("web", "127.0.0.1")
    job_id = ScanJobRepository().create(server_id)
    FindingRepository().bulk_insert(job_id, [{**payload, "rule_id": rule_id}])
    return job_id


def test_preview_requires_auth(client):
    response = client.post("/api/fixes/preview?job_id=1")

    assert response.status_code == 401


def test_nginx_finding_returns_safe_plan(client):
    login(client)
    job_id = _job_with_finding("NGX-SEC-2")

    response = client.post(f"/api/fixes/preview?job_id={job_id}")

    assert response.status_code == 200
    plan = response.json()["plans"][0]
    assert plan["can_auto_fix"] is False
    assert plan["backup_commands"]
    assert plan["validate_commands"]
    assert plan["rollback_commands"]


def test_unknown_rule_returns_non_auto_fix_plan(client):
    login(client)
    job_id = _job_with_finding("UNKNOWN-1")

    response = client.post(f"/api/fixes/preview?job_id={job_id}")

    assert response.status_code == 200
    plan = response.json()["plans"][0]
    assert plan["can_auto_fix"] is False
    assert plan["risk"] == "unknown"


def test_sensitive_path_finding_returns_block_and_validate_plan(client):
    login(client)
    job_id = _job_with_finding_payload(
        "HTTP-PROBE-005",
        {
            "severity": "critical",
            "title": "Sensitive path is publicly exposed",
            "evidence_ref": "/etc/nginx/sites-enabled/app.conf",
            "evidence_json": (
                '[{"excerpt":"https://example.test/composer.json => HTTP 200",'
                '"command":"curl -I https://example.test/composer.json"}]'
            ),
        },
    )

    response = client.post(f"/api/fixes/preview?job_id={job_id}")

    assert response.status_code == 200
    plan = response.json()["plans"][0]
    assert plan["risk"] == "high"
    assert plan["backup_commands"]
    assert any("composer.json" in command["command"] for command in plan["apply_commands"])
    assert any("403 or 404" in warning for warning in plan["warnings"])
    assert any(
        "example.test/composer.json" in command["command"]
        for command in plan["validate_commands"]
    )


def test_tls_expiry_finding_returns_certbot_validation_plan(client):
    login(client)
    job_id = _job_with_finding_payload(
        "DNS-TLS-005",
        {
            "severity": "warning",
            "title": "TLS certificate expires soon",
            "evidence_ref": "certbot",
        },
    )

    response = client.post(f"/api/fixes/preview?job_id={job_id}")

    assert response.status_code == 200
    plan = response.json()["plans"][0]
    assert plan["risk"] == "medium"
    assert any(
        "certbot renew --dry-run" in command["command"]
        for command in plan["apply_commands"]
    )
    assert any("openssl s_client" in command["command"] for command in plan["validate_commands"])
    assert plan["rollback_commands"]


def test_dotted_dependency_rule_gets_dependency_plan(client):
    login(client)
    job_id = _job_with_finding_payload(
        "SC-DEP-003.2",
        {
            "severity": "warning",
            "title": "Dependency vulnerability",
            "evidence_ref": "/srv/app/package.json",
        },
    )

    response = client.post(f"/api/fixes/preview?job_id={job_id}")

    assert response.status_code == 200
    plan = response.json()["plans"][0]
    assert plan["risk"] == "medium"
    assert any("audit" in command["command"] for command in plan["apply_commands"])


def test_informational_tls_rule_returns_no_action_plan(client):
    login(client)
    job_id = _job_with_finding("DNS-TLS-012")

    response = client.post(f"/api/fixes/preview?job_id={job_id}")

    assert response.status_code == 200
    plan = response.json()["plans"][0]
    assert plan["risk"] == "low"
    assert "No remediation is required" in plan["summary"]
    assert plan["apply_commands"] == []
