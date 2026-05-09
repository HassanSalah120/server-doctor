"""CI/CD API routes for server-doctor web app.

Provides endpoints for CI/CD integrations, API tokens, and export formats.
"""

import json
from datetime import datetime
from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from server_doctor.actions.cicd_formatter import CICDFormatter, SARIFFormatter
from server_doctor.storage.repositories import ScanJobRepository, ServerRepository
from server_doctor.web.job_runner import get_runner
from server_doctor.web.security import require_auth, require_csrf

router = APIRouter(prefix="/cicd", tags=["ci-cd"], dependencies=[Depends(require_auth)])


class CICDExportRequest(BaseModel):
    """Request to export scan results in CI/CD format."""
    job_id: int
    format: str = Field(default="json", pattern="^(json|sarif|github|junit)$")
    fail_on_warning: bool = False


class CICDExportResponse(BaseModel):
    """CI/CD export response."""
    job_id: int
    format: str
    content: dict[str, Any]
    exit_code: int
    summary: dict[str, Any]


class APITokenCreate(BaseModel):
    """Create API token request."""
    name: str
    server_ids: list[int] = []
    permissions: list[str] = ["scan:read", "report:read"]


class APITokenResponse(BaseModel):
    """API token response."""
    id: str
    name: str
    token: str
    created_at: str
    permissions: list[str]


class WebhookConfig(BaseModel):
    """Webhook configuration."""
    url: str
    headers: dict[str, str] = {}
    events: list[str] = ["scan.completed", "finding.critical"]
    secret: str | None = None


@router.post("/export", response_model=CICDExportResponse, dependencies=[Depends(require_csrf)])
async def export_scan_results(request: CICDExportRequest) -> CICDExportResponse:
    """Export scan results in CI/CD format (JSON, SARIF, GitHub, JUnit)."""
    job_repo = ScanJobRepository()
    job = job_repo.get_by_id(request.job_id)
    
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")
    
    if job.status != "completed":
        raise HTTPException(status_code=400, detail="Job not completed yet")
    
    # Get findings from report
    findings = job.report.findings if job.report else []
    
    # Format based on request
    if request.format == "sarif":
        content = SARIFFormatter.format(findings)
    elif request.format == "github":
        content = CICDFormatter.format_findings(
            findings,
            server_id=job.server_id,
            server_name=job.server.name if job.server else None,
        )
        content["github"] = {
            "annotations": content.get("annotations", []),
            "summary": f"Found {content['summary']['critical']} critical, {content['summary']['warning']} warnings"
        }
    elif request.format == "junit":
        content = _format_junit(findings, job.id)
    else:
        content = CICDFormatter.format_findings(
            findings,
            server_id=job.server_id,
            server_name=job.server.name if job.server else None,
        )
    
    exit_code = CICDFormatter.get_exit_code(findings, request.fail_on_warning)
    
    return CICDExportResponse(
        job_id=request.job_id,
        format=request.format,
        content=content,
        exit_code=exit_code,
        summary=content.get("summary", {}),
    )


def _format_junit(findings: list, job_id: int) -> dict[str, Any]:
    """Format findings as JUnit XML for CI integration."""
    critical = [f for f in findings if f.severity.value == "critical"]
    warnings = [f for f in findings if f.severity.value == "warning"]
    
    testcases = []
    for finding in findings:
        status = "failure" if finding.severity.value == "critical" else "skipped" if finding.severity.value == "warning" else "passed"
        testcases.append({
            "name": finding.id,
            "classname": "server-doctor",
            "status": status,
            "message": finding.condition,
            "details": finding.cause,
        })
    
    return {
        "testsuite": {
            "name": f"server-doctor-scan-{job_id}",
            "tests": len(findings),
            "failures": len(critical),
            "skipped": len(warnings),
            "testcases": testcases,
        }
    }


@router.get("/jobs/{job_id}/status")
async def get_job_status_for_cicd(job_id: int) -> dict[str, Any]:
    """Get job status in CI/CD friendly format."""
    job_repo = ScanJobRepository()
    job = job_repo.get_by_id(job_id)
    
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")
    
    findings = job.report.findings if job.report else []
    critical = len([f for f in findings if f.severity.value == "critical"])
    warning = len([f for f in findings if f.severity.value == "warning"])
    
    return {
        "job_id": job_id,
        "status": job.status,
        "server_id": job.server_id,
        "created_at": job.created_at.isoformat() if job.created_at else None,
        "completed_at": job.completed_at.isoformat() if job.completed_at else None,
        "summary": {
            "critical": critical,
            "warning": warning,
            "total": len(findings),
            "passed": critical == 0 and warning == 0,
        },
        "logs_url": f"/api/scan/jobs/{job_id}/logs",
        "report_url": f"/reports/{job_id}",
    }


@router.post("/tokens", response_model=APITokenResponse, dependencies=[Depends(require_csrf)])
async def create_api_token(request: APITokenCreate) -> APITokenResponse:
    """Create API token for CI/CD integration."""
    import secrets
    import hashlib
    
    token = secrets.token_urlsafe(32)
    token_id = hashlib.sha256(token.encode()).hexdigest()[:16]
    
    # Store token (in real implementation, hash it)
    # For now, return the token
    
    return APITokenResponse(
        id=token_id,
        name=request.name,
        token=token,  # Only shown once
        created_at=datetime.utcnow().isoformat(),
        permissions=request.permissions,
    )


@router.post("/webhooks", dependencies=[Depends(require_csrf)])
async def configure_webhook(config: WebhookConfig) -> dict[str, Any]:
    """Configure webhook for CI/CD notifications."""
    # Store webhook config
    return {
        "id": secrets.token_hex(8),
        "url": config.url,
        "events": config.events,
        "active": True,
        "created_at": datetime.utcnow().isoformat(),
    }


@router.get("/integrations/github-action")
async def get_github_action_config() -> dict[str, Any]:
    """Get GitHub Actions workflow configuration."""
    return {
        "name": "server-doctor-scan",
        "on": ["push", "schedule"],
        "jobs": {
            "scan": {
                "runs-on": "ubuntu-latest",
                "steps": [
                    {
                        "name": "Run server-doctor scan",
                        "uses": "server-doctor/action@v1",
                        "with": {
                            "server": "${{ secrets.server_doctor_SERVER }}",
                            "api-token": "${{ secrets.server_doctor_TOKEN }}",
                            "format": "sarif",
                        }
                    },
                    {
                        "name": "Upload SARIF",
                        "uses": "github/codeql-action/upload-sarif@v2",
                        "with": {"sarif_file": "results.sarif"}
                    }
                ]
            }
        }
    }
