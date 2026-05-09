"""
Apply API routes.

Endpoint:
- POST /api/apply-setup - Queue apply job with safety checks
"""

from typing import Optional
from pydantic import BaseModel, Field

from fastapi import APIRouter, Depends, HTTPException

from server_doctor.web.session import session_store
from server_doctor.web.jobs import job_executor
from server_doctor.web.safe_apply import run_safe_apply
from server_doctor.web.routes.preview import PreviewRequest, preview_setup
from server_doctor.web.security import require_auth, require_csrf


router = APIRouter(dependencies=[Depends(require_auth)])


class ApplyConfirmation(BaseModel):
    """Confirmation for apply operation."""
    typed: str = Field(..., description="Must be exactly 'APPLY'")
    ack: bool = Field(..., description="Must be true")


class ApplyRequest(BaseModel):
    """Apply setup request."""
    host_id: str = Field(..., description="Session ID from connect")
    domain: str = Field(..., description="Target domain")
    path: str = Field(..., description="URL path")
    project_type: str = Field(..., description="laravel | static | proxy")
    root: Optional[str] = Field(None, description="Filesystem root")
    php_version: str = Field("auto", description="PHP version")
    fpm_socket: str = Field("auto", description="PHP-FPM socket")
    proxy_target: Optional[str] = Field(None, description="For proxy type")
    websocket: Optional[dict] = None
    confirmation: ApplyConfirmation


class ApplyResponse(BaseModel):
    """Apply response."""
    job_id: str = Field(..., description="Job ID for status polling")


@router.post("/apply-setup", response_model=ApplyResponse, dependencies=[Depends(require_csrf)])
async def apply_setup(request: ApplyRequest) -> ApplyResponse:
    """Apply configuration changes.
    
    Requires typed confirmation 'APPLY' to proceed.
    Returns job_id for polling status.
    """
    try:
        # Validate confirmation
        if request.confirmation.typed != "APPLY":
            raise HTTPException(
                status_code=400,
                detail="Confirmation must type exactly 'APPLY'"
            )
        if not request.confirmation.ack:
            raise HTTPException(
                status_code=400,
                detail="Acknowledgement checkbox must be checked"
            )
        
        # Get session
        session = session_store.get_session(request.host_id)
        if not session:
            raise HTTPException(status_code=401, detail="Invalid or expired session")
        
        ssh = session.ssh
        host = session.host
        
        # First run preview to get the snippets and validate
        from server_doctor.web.routes.preview import WebSocketConfig
        
        ws_config = None
        if request.websocket:
            ws_config = WebSocketConfig(**request.websocket)
        
        preview_req = PreviewRequest(
            host_id=request.host_id,
            domain=request.domain,
            path=request.path,
            project_type=request.project_type,
            root=request.root,
            php_version=request.php_version,
            fpm_socket=request.fpm_socket,
            proxy_target=request.proxy_target,
            websocket=ws_config,
        )
        
        # Generate preview (validates and creates snippets)
        preview = await preview_setup(preview_req)
        
        # Check for blocking issues
        if preview.validation.marker_exists:
            raise HTTPException(
                status_code=409,
                detail=f"Project marker for {request.path} already exists. Cannot insert duplicate."
            )
        
        # Create job
        job = job_executor.create_job()
        
        # Get host lock for mutex
        host_lock = session_store.get_host_lock(host)
        
        # Run apply in background
        def apply_task(j: any) -> None:
            run_safe_apply(
                ssh=ssh,
                job=j,
                nginx_file=preview.nginx_file,
                domain=request.domain,
                snippet=preview.nginx_snippet,
                websocket_snippet=preview.websocket_snippet,
            )
        
        job_executor.run_in_background(job, apply_task, host_lock)
        
        return ApplyResponse(job_id=job.id)
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Apply failed: {str(e)}")
