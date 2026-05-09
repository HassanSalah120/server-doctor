"""Helpers for authenticated web API tests."""


def login(client, password: str = "test-password") -> str:
    response = client.post("/api/auth/login", json={"password": password})
    assert response.status_code == 200
    token = response.json().get("csrf_token")
    assert token
    return token


def csrf_headers(token: str) -> dict[str, str]:
    return {"x-serverdoctor-csrf": token}
