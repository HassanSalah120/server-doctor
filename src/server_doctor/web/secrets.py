"""OS keyring helpers for web-created SSH secrets."""

from __future__ import annotations

import secrets

import keyring

SERVICE_NAME = "server-doctor-web"


class SecretStorageError(RuntimeError):
    """Raised when password storage cannot complete safely."""


def make_secret_ref(server_name: str, host: str, kind: str = "password") -> str:
    suffix = secrets.token_hex(8)
    return f"{kind}:{server_name}:{host}:{suffix}"


def store_server_password(server_name: str, host: str, password: str) -> str:
    ref = make_secret_ref(server_name, host, kind="password")
    try:
        keyring.set_password(SERVICE_NAME, ref, password)
    except Exception as exc:  # pragma: no cover - exercised through route tests with mocks
        raise SecretStorageError(f"Failed to store SSH password in OS keyring: {exc}") from exc
    return ref


def store_server_key_passphrase(server_name: str, host: str, passphrase: str) -> str:
    ref = make_secret_ref(server_name, host, kind="key-passphrase")
    try:
        keyring.set_password(SERVICE_NAME, ref, passphrase)
    except Exception as exc:  # pragma: no cover - exercised through route tests with mocks
        raise SecretStorageError(
            f"Failed to store SSH key passphrase in OS keyring: {exc}"
        ) from exc
    return ref


def get_server_password(ref: str | None) -> str | None:
    if not ref:
        return None
    try:
        return keyring.get_password(SERVICE_NAME, ref)
    except Exception as exc:
        raise SecretStorageError(f"Failed to read SSH password from OS keyring: {exc}") from exc


def get_server_key_passphrase(ref: str | None) -> str | None:
    if not ref:
        return None
    try:
        return keyring.get_password(SERVICE_NAME, ref)
    except Exception as exc:
        raise SecretStorageError(
            f"Failed to read SSH key passphrase from OS keyring: {exc}"
        ) from exc


def delete_server_password(ref: str | None) -> None:
    if not ref:
        return
    try:
        keyring.delete_password(SERVICE_NAME, ref)
    except Exception:
        pass


def delete_server_key_passphrase(ref: str | None) -> None:
    if not ref:
        return
    try:
        keyring.delete_password(SERVICE_NAME, ref)
    except Exception:
        pass
