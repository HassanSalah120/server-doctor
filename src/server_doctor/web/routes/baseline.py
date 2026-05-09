"""Accepted-risk baseline API routes."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from server_doctor.engine.finding_fingerprint import fingerprint_record
from server_doctor.storage.repositories import (
    AcceptedRiskRepository,
    FindingRepository,
    LifecycleEventRepository,
    ScanJobRepository,
    ServerRepository,
)
from server_doctor.web.security import require_auth, require_csrf

router = APIRouter(
    prefix="/baseline",
    tags=["baseline"],
    dependencies=[Depends(require_auth)],
)


class AcceptRiskRequest(BaseModel):
    finding_id: int
    reason: str
    accepted_by: str = "local-user"
    expires_at: str | None = None


class AcceptedRiskResponse(BaseModel):
    id: int
    server_id: int
    rule_id: str
    finding_title: str | None
    reason: str
    accepted_by: str
    expires_at: str | None
    created_at: str


@router.post(
    "/accept",
    response_model=AcceptedRiskResponse,
    dependencies=[Depends(require_csrf)],
)
async def accept_risk(request: AcceptRiskRequest) -> AcceptedRiskResponse:
    if not request.reason.strip():
        raise HTTPException(status_code=400, detail="Acceptance reason is required")

    finding = FindingRepository().get_by_id(request.finding_id)
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")
    job = ScanJobRepository().get_by_id(finding.job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")
    if not ServerRepository().get_by_id(job.server_id):
        raise HTTPException(status_code=404, detail="Server not found")

    repo = AcceptedRiskRepository()
    risk_id = repo.create(
        server_id=job.server_id,
        rule_id=finding.rule_id,
        finding_title=finding.title,
        reason=request.reason.strip(),
        accepted_by=request.accepted_by.strip() or "local-user",
        expires_at=request.expires_at,
    )
    fingerprint, target = fingerprint_record(job.server_id, finding)
    LifecycleEventRepository().create(
        server_id=job.server_id,
        job_id=finding.job_id,
        finding_fingerprint=fingerprint,
        rule_id=finding.rule_id,
        target=target,
        event_type="accepted_risk",
        source="baseline_api",
        details={
            "accepted_risk_id": risk_id,
            "reason": request.reason.strip(),
            "accepted_by": request.accepted_by.strip() or "local-user",
            "expires_at": request.expires_at,
        },
    )
    record = next(item for item in repo.get_by_server_id(job.server_id) if item.id == risk_id)
    return AcceptedRiskResponse(**record.to_dict())


@router.get("/servers/{server_id}", response_model=list[AcceptedRiskResponse])
async def list_accepted_risks(server_id: int) -> list[AcceptedRiskResponse]:
    if not ServerRepository().get_by_id(server_id):
        raise HTTPException(status_code=404, detail="Server not found")
    return [
        AcceptedRiskResponse(**record.to_dict())
        for record in AcceptedRiskRepository().get_by_server_id(server_id)
    ]
