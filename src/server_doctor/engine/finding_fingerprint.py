"""Stable finding fingerprints for lifecycle and regression tracking."""

from __future__ import annotations

import hashlib
import json
import re
from urllib.parse import urlsplit, urlunsplit

from server_doctor.storage.models import FindingRecord

URL_RE = re.compile(r"https?://[^\s;,)]+", re.I)


def fingerprint_finding(
    server_id: int,
    rule_id: str,
    target: str | None,
    evidence_key: str | None,
) -> str:
    stable_target = normalize_target(target or evidence_key or "unknown")
    raw = f"{server_id}|{rule_id}|{stable_target}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def fingerprint_record(server_id: int, finding: FindingRecord) -> tuple[str, str]:
    target = extract_target(finding)
    evidence_key = extract_evidence_key(finding)
    return (
        fingerprint_finding(server_id, finding.rule_id, target, evidence_key),
        normalize_target(target or evidence_key or "unknown"),
    )


def normalize_target(value: str | None) -> str:
    text = (value or "").strip()
    if not text:
        return "unknown"

    if URL_RE.match(text):
        parsed = urlsplit(text)
        scheme = parsed.scheme.lower()
        netloc = parsed.netloc.lower()
        path = _normalize_path(parsed.path or "/")
        if path != "/":
            path = path.rstrip("/")
        return urlunsplit((scheme, netloc, path, parsed.query, ""))

    if text.startswith("/"):
        return _normalize_path(text).rstrip("/") or "/"

    return " ".join(text.split()).lower()


def extract_target(finding: FindingRecord) -> str | None:
    for value in _evidence_values(finding):
        match = URL_RE.search(value)
        if match:
            return match.group(0)
    for value in (finding.evidence_ref, finding.title, finding.description):
        if not value:
            continue
        match = URL_RE.search(value)
        if match:
            return match.group(0)
        if str(value).startswith("/"):
            return str(value)
    return None


def extract_evidence_key(finding: FindingRecord) -> str | None:
    values = _evidence_values(finding)
    if values:
        return values[0]
    return finding.evidence_ref or finding.title or finding.rule_id


def _normalize_path(path: str) -> str:
    return re.sub(r"/+", "/", path)


def _evidence_values(finding: FindingRecord) -> list[str]:
    if not finding.evidence_json:
        return []
    try:
        parsed = json.loads(finding.evidence_json)
    except json.JSONDecodeError:
        return []
    if not isinstance(parsed, list):
        return []
    values: list[str] = []
    for item in parsed:
        if not isinstance(item, dict):
            continue
        for key in ("source_file", "excerpt", "command"):
            value = item.get(key)
            if isinstance(value, str) and value.strip():
                values.append(value.strip())
    return values
