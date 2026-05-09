"""Recursive redaction helpers for reports and support packs."""

from __future__ import annotations

import copy
import re
from typing import Any

SECRET_PATTERNS = [
    re.compile(r"(?i)(password\s*=\s*)[^\s]+"),
    re.compile(r"(?i)(secret\s*=\s*)[^\s]+"),
    re.compile(r"(?i)(token\s*=\s*)[^\s]+"),
    re.compile(r"(?i)(api[_-]?key\s*=\s*)[^\s]+"),
    re.compile(r"(?i)(DB_PASSWORD\s*=\s*).+"),
    re.compile(r"(?i)(APP_KEY\s*=\s*).+"),
    re.compile(r"(?i)(webhook[_-]?url\s*=\s*)[^\s]+"),
    re.compile(
        r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----",
        re.S,
    ),
]

SENSITIVE_KEYS = {
    "password",
    "passwd",
    "secret",
    "token",
    "api_key",
    "apikey",
    "app_key",
    "db_password",
    "webhook_url",
    "private_key",
}


def redact_text(value: str) -> str:
    redacted = value
    for pattern in SECRET_PATTERNS:
        if pattern.groups:
            redacted = pattern.sub(lambda m: f"{m.group(1)}<redacted>", redacted)
        else:
            redacted = pattern.sub("<redacted>", redacted)
    return redacted


def redact_value(value: Any) -> Any:
    """Return a redacted deep copy without mutating the input."""
    if isinstance(value, str):
        return redact_text(value)
    if isinstance(value, list):
        return [redact_value(item) for item in value]
    if isinstance(value, tuple):
        return tuple(redact_value(item) for item in value)
    if isinstance(value, dict):
        result: dict[Any, Any] = {}
        for key, item in value.items():
            key_text = str(key).strip().lower()
            normalized = key_text.replace("-", "_")
            if normalized in SENSITIVE_KEYS:
                result[key] = "<redacted>"
            else:
                result[key] = redact_value(item)
        return result
    return copy.deepcopy(value)
