"""Daemon monitoring routes for server-doctor web app.

Provides web API for continuous monitoring daemon control.
"""

import os
import tempfile
from datetime import datetime
from typing import Any

from fastapi import APIRouter, Body, Depends, HTTPException
from pydantic import BaseModel, Field

from server_doctor.daemon.monitor import MonitoringDaemon
from server_doctor.config import ConfigManager
from server_doctor.connector.ssh import SSHConfig
from server_doctor.storage.repositories import ServerRepository
from server_doctor.web.secrets import get_server_key_passphrase, get_server_password
from server_doctor.web.security import require_auth, require_csrf

router = APIRouter(prefix="/daemon", tags=["daemon"], dependencies=[Depends(require_auth)])

# Use platform-appropriate temp directory
PID_FILE = os.path.join(tempfile.gettempdir(), "server-doctor-web.pid")


class DaemonStartRequest(BaseModel):
    """Request to start monitoring daemon."""
    interval: int = Field(default=3600, ge=60, le=86400, description="Scan interval in seconds")
    server_ids: list[int] = Field(default=[], description="Server IDs to monitor (empty = all)")
    notification_enabled: bool = True


class DaemonStatusResponse(BaseModel):
    """Daemon status response."""
    running: bool
    pid: int | None
    started_at: str | None
    interval: int
    servers: list[int]
    last_scan: str | None
    next_scan: str | None
    scan_count: int
    error_count: int


class DaemonHistoryEntry(BaseModel):
    """Recent daemon activity entry."""
    timestamp: str
    server: str
    status: str
    message: str | None = None
    new_findings: int | None = None
    resolved_findings: int | None = None
    findings_total: int | None = None


class DaemonConfig(BaseModel):
    """Daemon configuration."""
    interval: int = 3600
    auto_start: bool = False
    notify_on_critical: bool = True
    notify_on_warning: bool = False
    max_retries: int = 3


# Global daemon instance
daemon_instance: MonitoringDaemon | None = None


@router.post("/start", dependencies=[Depends(require_csrf)])
async def start_daemon(request: DaemonStartRequest) -> dict[str, Any]:
    """Start the monitoring daemon."""
    global daemon_instance
    
    if daemon_instance and daemon_instance.is_running():
        raise HTTPException(status_code=400, detail="Daemon already running")
    
    # Get server names from IDs
    config_mgr = ConfigManager()
    server_names = None
    server_repo = ServerRepository()
    servers = None
    if request.server_ids:
        servers = [server_repo.get_by_id(sid) for sid in request.server_ids]
        servers = [s for s in servers if s]
    else:
        servers = server_repo.get_all()

    server_names = [s.name for s in servers]

    # Sync web server records into ConfigManager profiles so the daemon can load them
    for s in servers:
        config_mgr.add_profile(
            s.name,
            SSHConfig(
                host=s.host,
                user=s.username,
                port=s.port,
                key_path=s.key_path,
                passphrase=get_server_key_passphrase(s.key_passphrase_secret_ref),
                use_sudo=True,
                password=get_server_password(s.password_secret_ref) or s.password,
            ),
        )
    
    daemon_instance = MonitoringDaemon(
        config_mgr=config_mgr,
        interval=request.interval,
        servers=server_names,
        pid_file=PID_FILE,
    )
    
    # Start in background (non-blocking for web)
    import threading
    daemon_error = [None]  # Use list to allow mutation in nested function
    
    def run_daemon():
        try:
            daemon_instance.start()
        except Exception as e:
            daemon_error[0] = str(e)
            print(f"Daemon error: {e}")
    
    thread = threading.Thread(target=run_daemon, daemon=True)
    thread.start()
    
    # Wait a moment for daemon to initialize
    import time
    time.sleep(0.5)
    
    # Check if daemon actually started
    if not daemon_instance.is_running():
        error_msg = daemon_error[0] or "Unknown error"
        raise HTTPException(status_code=500, detail=f"Daemon failed to start: {error_msg}")
    
    return {
        "status": "started",
        "interval": request.interval,
        "servers": request.server_ids,
        "pid_file": PID_FILE,
    }


@router.post("/stop", dependencies=[Depends(require_csrf)])
async def stop_daemon() -> dict[str, Any]:
    """Stop the monitoring daemon."""
    global daemon_instance
    
    if daemon_instance:
        daemon_instance.stop()
        daemon_instance = None
    
    # Also check PID file
    daemon = MonitoringDaemon(pid_file=PID_FILE)
    if daemon.is_running():
        daemon.stop()
    
    return {"status": "stopped"}


@router.get("/status", response_model=DaemonStatusResponse)
async def get_daemon_status() -> DaemonStatusResponse:
    """Get daemon status."""
    global daemon_instance
    
    # Check both global instance and PID file
    daemon = daemon_instance or MonitoringDaemon(pid_file=PID_FILE)
    
    running = daemon.is_running()
    info = daemon.get_info()

    interval = info.get("interval", 3600)

    server_repo = ServerRepository()
    requested_servers = info.get("servers")

    server_ids: list[int] = []
    if requested_servers == "all" or requested_servers is None:
        server_ids = [s.id for s in server_repo.get_all()]
    elif isinstance(requested_servers, list):
        name_to_id = {s.name: s.id for s in server_repo.get_all()}
        server_ids = [name_to_id[name] for name in requested_servers if name in name_to_id]

    return DaemonStatusResponse(
        running=running,
        pid=info.get("pid"),
        started_at=info.get("started_at"),
        interval=interval,
        servers=server_ids,
        last_scan=info.get("last_scan"),
        next_scan=info.get("next_scan"),
        scan_count=int(info.get("scan_count", 0) or 0),
        error_count=int(info.get("error_count", 0) or 0),
    )


@router.get("/config")
async def get_daemon_config() -> DaemonConfig:
    """Get daemon configuration."""
    config_mgr = ConfigManager()
    config = config_mgr.get_notification("daemon") or {}
    
    return DaemonConfig(
        interval=config.get("interval", 3600),
        auto_start=config.get("auto_start", False),
        notify_on_critical=config.get("notify_on_critical", True),
        notify_on_warning=config.get("notify_on_warning", False),
        max_retries=config.get("max_retries", 3),
    )


@router.post("/config", dependencies=[Depends(require_csrf)])
async def update_daemon_config(config: DaemonConfig) -> DaemonConfig:
    """Update daemon configuration."""
    config_mgr = ConfigManager()
    config_mgr.set_notification("daemon", config.dict())
    
    return config


@router.get("/history", response_model=list[DaemonHistoryEntry])
async def get_scan_history(limit: int = 10) -> list[DaemonHistoryEntry]:
    """Get recent scan history from daemon."""
    daemon = daemon_instance or MonitoringDaemon(pid_file=PID_FILE)
    events = daemon.get_history(limit=max(1, min(limit, 200)))
    return [DaemonHistoryEntry(**event) for event in events]


@router.post("/scan-now", dependencies=[Depends(require_csrf)])
async def trigger_manual_scan(
    server_ids: list[int] | None = Body(default=None),
) -> dict[str, Any]:
    """Trigger immediate scan via daemon."""
    global daemon_instance
    
    if not daemon_instance or not daemon_instance.is_running():
        raise HTTPException(status_code=400, detail="Daemon not running")
    
    server_repo = ServerRepository()

    effective_server_ids: list[int] = []

    if server_ids:
        effective_server_ids = server_ids
        id_to_name = {s.id: s.name for s in server_repo.get_all()}
        names = [id_to_name[sid] for sid in server_ids if sid in id_to_name]

        # Trigger scan for only the selected servers
        import threading

        def trigger():
            for name in names:
                daemon_instance._scan_server(name)

        thread = threading.Thread(target=trigger)
        thread.start()

    else:
        # No explicit server_ids provided: return and scan the daemon-configured monitored servers.
        info = daemon_instance.get_info()
        requested_servers = info.get("servers")

        if requested_servers == "all" or requested_servers is None:
            effective_server_ids = [s.id for s in server_repo.get_all()]
        elif isinstance(requested_servers, list):
            name_to_id = {s.name: s.id for s in server_repo.get_all()}
            effective_server_ids = [name_to_id[name] for name in requested_servers if name in name_to_id]

        # Trigger one scan cycle (uses daemon_instance.servers)
        import threading

        def trigger():
            daemon_instance._run_scan_cycle()

        thread = threading.Thread(target=trigger)
        thread.start()

    return {
        "status": "scan_triggered",
        "servers": effective_server_ids,
        "timestamp": datetime.utcnow().isoformat(),
    }
