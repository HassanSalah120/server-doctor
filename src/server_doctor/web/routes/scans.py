"""Scan job API routes.

Endpoints:
    POST /api/scan      - Start a scan job
    GET  /api/jobs      - List all scan jobs
    GET  /api/jobs/{id} - Get job detail + logs (for live polling)
"""

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from server_doctor.storage.repositories import (
    JobLogRepository,
    ScanJobRepository,
    ServerRepository,
)
from server_doctor.web.job_runner import get_runner
from server_doctor.web.security import require_auth, require_csrf

router = APIRouter(dependencies=[Depends(require_auth)])
_job_repo = ScanJobRepository()
_log_repo = JobLogRepository()
_server_repo = ServerRepository()


class ScanRequest(BaseModel):
    """Request body for starting a scan."""

    server_id: int = Field(..., description="ID of the server to scan")
    devops_enabled: bool | None = Field(
        default=None,
        description="Deprecated: DevOps checks are always enabled.",
    )
    repo_scan_paths: str | None = Field(
        default=None,
        description=(
            "Optional comma-separated repo paths for DevOps scanning "
            "(e.g., /path/to/repo1,/path/to/repo2). If omitted, paths are auto-discovered."
        ),
    )
    one_time_password: str | None = Field(
        default=None,
        description="Session-only SSH password for this scan. It is never persisted.",
    )
    one_time_key_passphrase: str | None = Field(
        default=None,
        description=(
            "Session-only SSH key passphrase for this scan. It is never persisted."
        ),
    )


@router.post("/scan", dependencies=[Depends(require_csrf)])
async def start_scan(request: ScanRequest) -> dict:
    """Start a new scan job for a server."""
    # Verify server exists
    server = _server_repo.get_by_id(request.server_id)
    if not server:
        raise HTTPException(status_code=404, detail="Server not found")

    try:
        runner = get_runner()
        job_id = runner.submit_scan(
            request.server_id,
            repo_scan_paths=request.repo_scan_paths,
            one_time_password=request.one_time_password,
            one_time_key_passphrase=request.one_time_key_passphrase,
        )
        return {"job_id": job_id, "status": "queued"}
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e)) from e
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to start scan: {str(e)}") from e


@router.get("/scan/jobs")
async def list_jobs() -> dict:
    """List all scan jobs with server info."""
    jobs = _job_repo.get_all()
    return {"jobs": [j.to_dict() for j in jobs]}


@router.get("/scan/jobs/{job_id}")
async def get_job(job_id: int, after_log_id: int = 0) -> dict:
    """Get job detail with logs.

    Supports efficient polling via after_log_id parameter —
    pass the last seen log ID to only receive new entries.
    """
    job = _job_repo.get_by_id(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")

    logs = _log_repo.get_by_job_id(job_id, after_id=after_log_id)

    return {
        "job": job.to_dict(),
        "logs": [log.to_dict() for log in logs],
    }


@router.post("/scan/jobs/{job_id}/cancel", dependencies=[Depends(require_csrf)])
async def cancel_job(job_id: int) -> dict:
    """Mark a queued or running job for cancellation."""
    job = _job_repo.get_by_id(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")

    if job.status not in ("queued", "running"):
        raise HTTPException(status_code=400, detail="Only queued or running jobs can be cancelled")

    _job_repo.update_status(job_id, "cancel_requested")
    _log_repo.append(job_id, "Cancellation requested by user")
    return {"status": "cancel_requested"}
