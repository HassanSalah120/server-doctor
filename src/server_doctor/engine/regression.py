"""Finding regression detection from lifecycle history."""

from __future__ import annotations

from dataclasses import asdict, dataclass

from server_doctor.engine.finding_fingerprint import fingerprint_record
from server_doctor.storage.models import FindingRecord, LifecycleEventRecord
from server_doctor.storage.repositories import (
    AcceptedRiskRepository,
    LifecycleEventRepository,
)


@dataclass
class RegressionMetadata:
    is_regression: bool
    resolved_in_job_id: int | None = None
    regressed_in_job_id: int | None = None
    regression_count: int = 0
    first_seen_at: str | None = None
    last_resolved_at: str | None = None

    def to_dict(self) -> dict:
        return asdict(self)


def is_regression(
    events: list[LifecycleEventRecord],
    current_job_id: int,
    accepted_active: bool,
) -> bool:
    if accepted_active:
        return False

    previous = [event for event in events if event.job_id != current_job_id]
    if not previous:
        return False

    latest_resolved = _latest_event(previous, "validated_resolved")
    latest_regression = _latest_event(previous, "regression")
    if not latest_resolved:
        return False
    return not (
        latest_regression and latest_regression.created_at > latest_resolved.created_at
    )


def regression_metadata(
    events: list[LifecycleEventRecord],
    current_job_id: int,
    accepted_active: bool = False,
) -> RegressionMetadata:
    detected_events = [event for event in events if event.event_type == "detected"]
    resolved_events = [
        event for event in events if event.event_type == "validated_resolved"
    ]
    regression_events = [
        event for event in events if event.event_type == "regression"
    ]
    latest_resolved = _latest_record(resolved_events)
    current_regression = is_regression(events, current_job_id, accepted_active)
    return RegressionMetadata(
        is_regression=current_regression,
        resolved_in_job_id=latest_resolved.job_id if latest_resolved else None,
        regressed_in_job_id=current_job_id if current_regression else None,
        regression_count=len(regression_events) + (1 if current_regression else 0),
        first_seen_at=detected_events[0].created_at if detected_events else None,
        last_resolved_at=latest_resolved.created_at if latest_resolved else None,
    )


def record_scan_lifecycle_events(
    *,
    server_id: int,
    job_id: int,
    findings: list[FindingRecord],
    lifecycle_repo: LifecycleEventRepository | None = None,
    accepted_risk_repo: AcceptedRiskRepository | None = None,
) -> None:
    lifecycle_repo = lifecycle_repo or LifecycleEventRepository()
    accepted_risk_repo = accepted_risk_repo or AcceptedRiskRepository()
    for finding in findings:
        fingerprint, target = fingerprint_record(server_id, finding)
        lifecycle_repo.create(
            server_id=server_id,
            job_id=job_id,
            finding_fingerprint=fingerprint,
            rule_id=finding.rule_id,
            target=target,
            event_type="detected",
            source="scan",
            details={
                "finding_id": finding.id,
                "severity": finding.severity,
                "title": finding.title,
            },
            idempotent=True,
        )
        accepted_active = accepted_risk_repo.is_accepted(
            server_id=server_id,
            rule_id=finding.rule_id,
            finding_title=finding.title,
        )
        events = lifecycle_repo.get_by_fingerprint(server_id, fingerprint)
        if is_regression(events, job_id, accepted_active):
            lifecycle_repo.create(
                server_id=server_id,
                job_id=job_id,
                finding_fingerprint=fingerprint,
                rule_id=finding.rule_id,
                target=target,
                event_type="regression",
                source="scan",
                details={
                    "finding_id": finding.id,
                    "severity": finding.severity,
                    "title": finding.title,
                },
                idempotent=True,
            )


def _latest_event(
    events: list[LifecycleEventRecord],
    event_type: str,
) -> LifecycleEventRecord | None:
    candidates = [event for event in events if event.event_type == event_type]
    return _latest_record(candidates)


def _latest_record(
    events: list[LifecycleEventRecord],
) -> LifecycleEventRecord | None:
    if not events:
        return None
    return max(events, key=lambda event: (event.created_at, event.id))
