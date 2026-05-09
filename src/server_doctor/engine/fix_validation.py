"""Targeted validation plans for stored findings."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Literal

from server_doctor.storage.models import FindingRecord
from server_doctor.utils.redaction import redact_text


@dataclass
class ValidationPlan:
    finding_id: int
    rule_id: str
    can_validate: bool
    command: str | None
    expected: str
    unresolved_statuses: list[int]
    summary: str


@dataclass
class ValidationResult:
    finding_id: int
    rule_id: str
    status: Literal["resolved", "still_failing", "not_validatable", "error"]
    command: str | None
    expected: str
    observed: str | None
    error: str | None = None


def build_validation_plan(finding: FindingRecord) -> ValidationPlan:
    """Build a registry-defined validation probe for a stored finding."""
    rule_id = finding.rule_id or "unknown"
    url = _extract_url(finding)

    if rule_id in {"HTTP-PROBE-005", "HTTP-PROBE-SOFT404"} and url:
        return ValidationPlan(
            finding_id=finding.id,
            rule_id=rule_id,
            can_validate=True,
            command=_curl_status_command(url),
            expected="HTTP status is 403 or 404",
            unresolved_statuses=[200, 206, 301, 302],
            summary="Re-probe sensitive path exposure.",
        )

    if rule_id in {"HTTP-PROBE-001", "HTTP-PROBE-007"} and url:
        return ValidationPlan(
            finding_id=finding.id,
            rule_id=rule_id,
            can_validate=True,
            command=_curl_status_command(url),
            expected="HTTP status is not 500, 502, 503, or 504",
            unresolved_statuses=[500, 502, 503, 504],
            summary="Re-probe upstream/application availability.",
        )

    if rule_id.startswith(("NGX-DEEP", "NGX-SEC", "PHPFPM-DEEP")):
        return ValidationPlan(
            finding_id=finding.id,
            rule_id=rule_id,
            can_validate=True,
            command="sudo nginx -t",
            expected="Nginx configuration test exits successfully",
            unresolved_statuses=[],
            summary="Validate Nginx configuration after manual remediation.",
        )

    return ValidationPlan(
        finding_id=finding.id,
        rule_id=rule_id,
        can_validate=False,
        command=None,
        expected="No targeted validation probe is registered for this rule.",
        unresolved_statuses=[],
        summary="No safe validation probe is available.",
    )


def evaluate_validation(
    finding: FindingRecord,
    *,
    stdout: str,
    stderr: str = "",
    exit_code: int = 0,
) -> ValidationResult:
    plan = build_validation_plan(finding)
    if not plan.can_validate:
        return ValidationResult(
            finding_id=finding.id,
            rule_id=finding.rule_id,
            status="not_validatable",
            command=plan.command,
            expected=plan.expected,
            observed=None,
        )

    observed = redact_text((stdout or stderr or "").strip())
    if exit_code != 0:
        return ValidationResult(
            finding_id=finding.id,
            rule_id=finding.rule_id,
            status="still_failing",
            command=plan.command,
            expected=plan.expected,
            observed=observed,
            error=redact_text(stderr) if stderr else f"exit_code={exit_code}",
        )

    status_code = _extract_status_code(stdout)
    if status_code is not None and status_code in plan.unresolved_statuses:
        status: Literal["resolved", "still_failing"] = "still_failing"
    else:
        status = "resolved"

    return ValidationResult(
        finding_id=finding.id,
        rule_id=finding.rule_id,
        status=status,
        command=plan.command,
        expected=plan.expected,
        observed=observed or f"exit_code={exit_code}",
    )


def _curl_status_command(url: str) -> str:
    safe_url = url.replace("'", "'\"'\"'")
    return f"curl -sk -o /dev/null -w '%{{http_code}}' --max-time 8 '{safe_url}'"


def _extract_url(finding: FindingRecord) -> str | None:
    for value in _evidence_values(finding):
        match = re.search(r"https?://[^\s;,)]+", value)
        if match:
            return match.group(0)
    for value in (finding.title, finding.description, finding.evidence_ref):
        if not value:
            continue
        match = re.search(r"https?://[^\s;,)]+", value)
        if match:
            return match.group(0)
    return None


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
        for key in ("excerpt", "command", "source_file"):
            value = item.get(key)
            if isinstance(value, str):
                values.append(value)
    return values


def _extract_status_code(text: str) -> int | None:
    match = re.search(r"\b([1-5]\d\d)\b", text or "")
    if not match:
        return None
    return int(match.group(1))
