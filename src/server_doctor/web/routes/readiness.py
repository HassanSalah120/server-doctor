"""Deployment readiness API."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException

from server_doctor.engine.finding_fingerprint import fingerprint_record
from server_doctor.engine.readiness import build_readiness
from server_doctor.engine.regression import regression_metadata
from server_doctor.storage.repositories import (
    AcceptedRiskRepository,
    FindingRepository,
    LifecycleEventRepository,
    ScanJobRepository,
)
from server_doctor.web.security import require_auth

router = APIRouter(dependencies=[Depends(require_auth)])
_jobs = ScanJobRepository()
_findings = FindingRepository()
_accepted = AcceptedRiskRepository()
_lifecycle = LifecycleEventRepository()


@router.get("/readiness/{job_id}")
async def get_readiness(job_id: int) -> dict:
    job = _jobs.get_by_id(job_id)
    if not job or job.status != "success":
        raise HTTPException(status_code=404, detail="No successful scan data for readiness")
    findings = [
        finding
        for finding in _findings.get_by_job_id(job_id)
        if not _accepted.is_accepted(
            server_id=job.server_id,
            rule_id=finding.rule_id,
            finding_title=finding.title,
        )
    ]
    regression_by_finding = {}
    for finding in findings:
        fingerprint, _target = fingerprint_record(job.server_id, finding)
        events = _lifecycle.get_by_fingerprint(job.server_id, fingerprint)
        regression_by_finding[finding.id] = regression_metadata(
            events,
            current_job_id=job_id,
        ).to_dict()
    readiness = build_readiness(
        job_id,
        findings,
        regression_by_finding=regression_by_finding,
    ).to_dict()
    readiness["accepted_risks"] = [
        risk.to_dict() for risk in _accepted.get_by_server_id(job.server_id)
    ]
    return readiness
