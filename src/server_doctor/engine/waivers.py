"""Waiver engine for accepted-risk suppressions."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import date
from pathlib import Path
from typing import Any

from server_doctor.model.finding import Finding


@dataclass
class WaiverRule:
    """Waiver matching rule."""

    id: str
    reason: str = ""
    condition_contains: str | None = None
    expires: date | None = None

    def is_active(self, on_date: date) -> bool:
        if self.expires is None:
            return True
        return on_date <= self.expires

    def matches(self, finding: Finding) -> bool:
        rid = self.id.strip().upper()
        fid = finding.id.strip().upper()
        prefix = fid.split("-")[0]

        id_match = fid == rid or fid.startswith(rid + "-") or prefix == rid
        if not id_match:
            return False

        if self.condition_contains:
            return self.condition_contains.lower() in finding.condition.lower()
        return True


def default_waiver_path() -> Path:
    """Default waiver file location."""
    return Path.home() / ".server-doctor" / "waivers.yaml"


def load_waiver_rules(path: str | Path | None) -> list[WaiverRule]:
    """Load waiver rules from YAML file.

    Supported formats:
    - waivers:
      - id: SSH-1
        reason: accepted
    - [ {id: SSH-1}, ... ]
    - { SSH-1: "reason", NGX000: "reason" }
    """
    if not path:
        return []

    waiver_file = Path(path).expanduser()
    if not waiver_file.exists():
        return []

    try:
        import yaml
    except Exception:
        return []

    try:
        raw = yaml.safe_load(waiver_file.read_text(encoding="utf-8")) or {}
    except Exception:
        return []

    entries: list[dict[str, Any]] = []
    if isinstance(raw, dict):
        if isinstance(raw.get("waivers"), list):
            entries = [e for e in raw["waivers"] if isinstance(e, dict)]
        else:
            # map format: {ID: reason}
            for key, value in raw.items():
                if isinstance(key, str):
                    entries.append({"id": key, "reason": str(value) if value is not None else ""})
    elif isinstance(raw, list):
        entries = [e for e in raw if isinstance(e, dict)]

    rules: list[WaiverRule] = []
    for entry in entries:
        rule_id = str(entry.get("id", "")).strip()
        if not rule_id:
            continue

        expires = _parse_expiry(entry.get("expires"))
        rule = WaiverRule(
            id=rule_id,
            reason=str(entry.get("reason", "")).strip(),
            condition_contains=_optional_str(entry.get("condition_contains")),
            expires=expires,
        )
        rules.append(rule)
    return rules


def apply_waivers(
    findings: list[Finding],
    rules: list[WaiverRule],
    on_date: date | None = None,
) -> tuple[list[Finding], list[dict[str, str]]]:
    """Filter waived findings and return (kept, suppressed metadata)."""
    if not rules:
        return findings, []

    now = on_date or date.today()
    active_rules = [r for r in rules if r.is_active(now)]
    if not active_rules:
        return findings, []

    kept: list[Finding] = []
    suppressed: list[dict[str, str]] = []

    for finding in findings:
        matched_rule = next((rule for rule in active_rules if rule.matches(finding)), None)
        if not matched_rule:
            kept.append(finding)
            continue

        suppressed.append(
            {
                "id": finding.id,
                "severity": finding.severity.value.upper(),
                "condition": finding.condition,
                "reason": matched_rule.reason or "Accepted risk (waived)",
                "rule_id": matched_rule.id,
            }
        )

    return kept, suppressed


def _optional_str(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    return text or None


def _parse_expiry(value: Any) -> date | None:
    if value is None:
        return None
    text = str(value).strip()
    if not text:
        return None
    try:
        return date.fromisoformat(text)
    except ValueError:
        return None
