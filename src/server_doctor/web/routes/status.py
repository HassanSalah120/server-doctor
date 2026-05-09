"""
Server Status API routes.

Endpoint:
- GET /api/status - Get server health and configuration status
"""

from typing import List, Optional
from pydantic import BaseModel

from fastapi import APIRouter, Depends, HTTPException, Query

from server_doctor.web.session import session_store
from server_doctor.scanner.nginx import NginxScanner
from server_doctor.web.security import require_auth

router = APIRouter(dependencies=[Depends(require_auth)])


class SiteInfo(BaseModel):
    """Information about an Nginx site/server block."""
    domains: List[str]
    root: Optional[str]
    config_file: str
    listen_ports: List[str]
    has_ssl: bool


class ServerStatus(BaseModel):
    """Overall server status."""
    hostname: str
    os_info: str
    nginx_version: str
    active_sites: List[SiteInfo]


@router.get("/status", response_model=ServerStatus)
async def get_server_status(host_id: str = Query(..., description="Session ID")) -> ServerStatus:
    """Get current server status and configuration."""
    session = session_store.get_session(host_id)
    if not session:
        raise HTTPException(status_code=401, detail="Invalid or expired session")
    
    ssh = session.ssh
    
    try:
        # Gather system info
        hostname = ssh.run("hostname").stdout.strip()
        os_info = ssh.run("cat /etc/os-release | grep PRETTY_NAME | cut -d= -f2 | tr -d '\"'").stdout.strip()
        nginx_version = ssh.run("nginx -v 2>&1").stdout.strip()  # nginx -v goes to stderr usually
        
        # Gather Nginx info
        scanner = NginxScanner(ssh)
        nginx_info = scanner.scan()
        
        active_sites = []
        for server in nginx_info.servers:
            # Filter out default catch-alls if they have no server_name or just "_"
            # But we might want to see them too. Let's include everything for now.
            
            # Extract ports
            ports = []
            for listen in server.listens:
                ports.append(str(listen.port) + (" (ssl)" if listen.ssl else ""))
            
            active_sites.append(SiteInfo(
                domains=server.server_names,
                root=server.root,
                config_file=server.source_file,
                listen_ports=ports,
                has_ssl=any(l.ssl for l in server.listens)
            ))
            
        return ServerStatus(
            hostname=hostname,
            os_info=os_info or "Unknown Linux",
            nginx_version=nginx_version,
            active_sites=active_sites
        )
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to fetch status: {str(e)}")
