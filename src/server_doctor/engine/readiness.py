"""Deployment readiness decision engine."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Literal

from server_doctor.storage.models import FindingRecord

BLOCKER_RULE_PREFIXES = [
    "HTTP-PROBE-005",
    "HTTP-PROBE-007",
    "NGX-DEEP-005",
    "PHPFPM-DEEP-001",
    "LARAVEL-RUNTIME-011",
    "MYSQL-DEEP-001",
    "REDIS-DEEP-001",
    "DNS-TLS-004",
    "DNS-TLS-005",   # SSL expiry <= 7 days
]

# OOM is only a blocker when the affected process/container is known.
# When process is unknown it becomes a warning or needs_verification.
CONDITIONAL_BLOCKER_PREFIXES = {
    "RES-1": "process=unknown",  # skip blocker when this string is in the title
}


@dataclass
class ReadinessCheck:
    key: str
    label: str
    status: Literal["pass", "warn", "fail", "unknown"]
    blockers: list[str]
    evidence: list[str]
    classification: str | None = None


@dataclass
class DeploymentReadiness:
    job_id: int
    ready: bool
    score: int
    blockers: list[str]
    warnings: list[str]
    checks: list[ReadinessCheck]
    needs_verification: list[str] = field(default_factory=list)
    score_explanation: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return asdict(self)


def is_blocker(rule_id: str) -> bool:
    return any(rule_id.startswith(prefix) for prefix in BLOCKER_RULE_PREFIXES)


def is_conditional_blocker(rule_id: str, title: str) -> bool:
    """Check if a finding would be a blocker if it meets evidence conditions."""
    skip_substr = CONDITIONAL_BLOCKER_PREFIXES.get(rule_id)
    if skip_substr and skip_substr in title:
        return False
    return rule_id in CONDITIONAL_BLOCKER_PREFIXES


def calibrate_score(
    findings: list[FindingRecord],
    blocker_titles: list[str],
    regression_by_finding: dict[int, dict] | None = None,
) -> tuple[int, list[str]]:
    """Calibrate readiness score with caps per blocker type."""
    regression_by_finding = regression_by_finding or {}
    blocker_rule_ids = {
        f.rule_id
        for f in findings
        if _classify_finding(f, regression_by_finding.get(f.id))
        in ("blocker_confirmed", "blocker_probable")
    }
    explanation: list[str] = []

    start = 100
    caps: list[int] = []

    # Site-down / 502 blocker → cap 30
    if "HTTP-PROBE-007" in blocker_rule_ids:
        caps.append(30)
        explanation.append("Score capped by: upstream failure / gateway error")

    # Public sensitive file exposed → cap 45
    if "HTTP-PROBE-005" in blocker_rule_ids:
        caps.append(45)
        explanation.append("Score capped by: public sensitive file exposed")

    # SSL expiry <= 7 days → cap 60
    if "DNS-TLS-005" in blocker_rule_ids:
        caps.append(60)
        explanation.append("Score capped by: TLS certificate expires soon")

    # OOM kills → cap 55 if known process, else 70 (but only if it's a blocker)
    oom_is_blocker = "RES-1" in blocker_rule_ids
    if oom_is_blocker:
        # Only reachable here if process is known (unknown → needs_verification, not blocker)
        caps.append(55)
        explanation.append("Score capped by: OOM kills with affected process identified")

    # Apply the most restrictive cap
    effective_cap = min(caps) if caps else 100

    # Additional blockers beyond the first: -10 each
    extra_blocker_penalty = max(0, len(blocker_titles) - 1) * 10
    if extra_blocker_penalty > 0:
        explanation.append(
            f"Additional penalty: {extra_blocker_penalty} points "
            f"for {len(blocker_titles)} blockers"
        )

    # Also penalize warnings
    warning_titles = [
        f.title for f in findings
        if _classify_finding(f, regression_by_finding.get(f.id)) == "warning"
    ]
    warning_penalty = len(warning_titles) * 3
    if warning_penalty > 0:
        explanation.append(
            f"Warning penalty: {warning_penalty} points "
            f"for {len(warning_titles)} warnings"
        )

    score = min(effective_cap, start - extra_blocker_penalty - warning_penalty)
    score = max(1, score)

    # Floor to 1 only if site is down or 4+ critical blockers exist
    site_down = "HTTP-PROBE-007" in blocker_rule_ids
    critical_blockers = sum(
        1 for f in findings if f.rule_id in blocker_rule_ids and f.severity == "critical"
    )
    if score < 15 and not site_down and critical_blockers < 4:
        score = max(15, score)

    return score, explanation


def _classify_finding(f: FindingRecord, regression_meta: dict | None = None) -> str:
    """Classify a finding for readiness decisions."""
    if regression_meta and regression_meta.get("is_regression"):
        if f.severity == "critical":
            return "blocker_confirmed"
        if f.severity == "warning":
            return "warning"

    # Confirmed blockers
    if f.rule_id in ("HTTP-PROBE-005", "HTTP-PROBE-007", "NGX-DEEP-005",
                      "MYSQL-DEEP-001", "REDIS-DEEP-001", "DNS-TLS-004",
                      "PHPFPM-DEEP-001", "LARAVEL-RUNTIME-011"):
        return "blocker_confirmed"

    # Conditional blocker: RES-1 with known process → blocker_confirmed
    if f.rule_id == "RES-1":
        skip_substr = CONDITIONAL_BLOCKER_PREFIXES.get("RES-1", "")
        if skip_substr and skip_substr in (f.title or ""):
            return "needs_verification"
        return "blocker_confirmed"

    # SSL expiry <= 7 days → blocker_probable (depends on renewal health)
    if f.rule_id == "DNS-TLS-005":
        return "blocker_probable"

    # Route-name-only sensitive paths → needs_verification
    if f.rule_id.startswith("HTTP-PROBE-008"):
        return "needs_verification"

    if f.severity == "warning":
        return "warning"
    return "needs_verification"


def _deduplicate_findings(findings: list[FindingRecord]) -> list[FindingRecord]:
    """Deduplicate and canonicalize findings before readiness evaluation."""
    CANONICAL_MAP = {
        "SSH-2": "HOST-002",
        "OPS-SSH-5": "HOST-004",
    }
    seen: dict[tuple[str, str], FindingRecord] = {}
    for f in findings:
        rule_id = CANONICAL_MAP.get(f.rule_id, f.rule_id)
        key = (rule_id, f.title or "")
        if key in seen:
            existing = seen[key]
            if existing.severity != "critical" and f.severity == "critical":
                seen[key] = f
        else:
            seen[key] = FindingRecord(
                id=f.id, job_id=f.job_id, rule_id=rule_id,
                category=f.category, component=f.component,
                severity=f.severity, title=f.title,
                description=f.description, evidence_ref=f.evidence_ref,
                evidence_json=f.evidence_json, recommendation=f.recommendation,
                created_at=f.created_at,
            )
    return list(seen.values())


def build_readiness(
    job_id: int,
    findings: list[FindingRecord],
    regression_by_finding: dict[int, dict] | None = None,
) -> DeploymentReadiness:
    regression_by_finding = regression_by_finding or {}
    findings = _deduplicate_findings(findings)
    blocker_titles: list[str] = []
    warning_titles: list[str] = []
    needs_verification_titles: list[str] = []
    blocker_classes: list[str] = []
    for f in findings:
        regression_meta = regression_by_finding.get(f.id)
        cls = _classify_finding(f, regression_meta)
        title = _readiness_title(f, regression_meta)
        if cls in ("blocker_confirmed", "blocker_probable"):
            blocker_titles.append(title)
            blocker_classes.append(cls)
        elif cls == "warning":
            warning_titles.append(title)
        else:
            needs_verification_titles.append(f.title)
    checks = [
        _category_check("web", "Web serving", findings, ("HTTP-PROBE",), regression_by_finding),
        _category_check("nginx", "Nginx config", findings, ("NGX-DEEP",), regression_by_finding),
        _category_check(
            "runtime",
            "PHP-FPM/Node backend",
            findings,
            ("PHPFPM-DEEP", "NODE-RUNTIME"),
            regression_by_finding,
        ),
        _category_check("database", "Database", findings, ("MYSQL-DEEP",), regression_by_finding),
        _category_check(
            "redis",
            "Redis/cache/queue",
            findings,
            ("REDIS-DEEP", "LARAVEL-RUNTIME"),
            regression_by_finding,
        ),
        _category_check("ssl_dns", "SSL/DNS", findings, ("DNS-TLS",), regression_by_finding),
        _category_check("backups", "Backups", findings, ("BACKUP-READY",), regression_by_finding),
    ]
    score, explanation = calibrate_score(findings, blocker_titles, regression_by_finding)
    return DeploymentReadiness(
        job_id=job_id,
        ready=not blocker_titles,
        score=score,
        blockers=blocker_titles,
        warnings=warning_titles,
        checks=checks,
        needs_verification=needs_verification_titles,
        score_explanation=explanation,
    )


def _category_check(
    key: str,
    label: str,
    findings: list[FindingRecord],
    prefixes: tuple[str, ...],
    regression_by_finding: dict[int, dict] | None = None,
) -> ReadinessCheck:
    regression_by_finding = regression_by_finding or {}
    relevant = [f for f in findings if f.rule_id.startswith(prefixes)]
    classifications = [
        _classify_finding(f, regression_by_finding.get(f.id))
        for f in relevant
    ]
    blockers = [
        _readiness_title(f, regression_by_finding.get(f.id))
        for f, c in zip(relevant, classifications, strict=True)
        if c in ("blocker_confirmed", "blocker_probable")
    ]
    worst = "pass"
    if "blocker_confirmed" in classifications or "blocker_probable" in classifications:
        worst = "fail"
    elif relevant:
        worst = "warn"
    return ReadinessCheck(
        key=key,
        label=label,
        status=worst,
        blockers=blockers,
        evidence=[f.rule_id for f in relevant],
        classification=", ".join(sorted({c for c in classifications if c != "pass"})) or None,
    )


def _readiness_title(finding: FindingRecord, regression_meta: dict | None = None) -> str:
    if regression_meta and regression_meta.get("is_regression"):
        return f"Regression: {finding.title}"
    return finding.title
