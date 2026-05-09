"""
Connection API routes.

Endpoints:
- POST /api/connect - Establish SSH session
- GET /api/domains - List Nginx domains
"""

from typing import Optional
from pydantic import BaseModel, Field

from fastapi import APIRouter, Depends, HTTPException

from server_doctor.connector.ssh import SSHConfig
from server_doctor.web.session import session_store
from server_doctor.scanner.nginx import NginxScanner
from server_doctor.web.security import require_auth, require_csrf


router = APIRouter(dependencies=[Depends(require_auth)])


class ConnectRequest(BaseModel):
    """SSH connection request."""
    host: str = Field(..., description="Server hostname or IP")
    username: str = Field(..., description="SSH username")
    port: int = Field(22, description="SSH port")
    key_path: Optional[str] = Field(None, description="Path to private key file")
    key_passphrase: Optional[str] = Field(
        None,
        description="Passphrase for encrypted private key",
    )
    password: Optional[str] = Field(None, description="SSH password (not recommended)")


class ConnectResponse(BaseModel):
    """Connection response."""
    host_id: str = Field(..., description="Session ID for subsequent requests")
    os_name: str = Field(..., description="Server OS name")
    nginx_version: str = Field(..., description="Nginx version")


class DomainInfo(BaseModel):
    """Domain information."""
    domain: str
    source_file: str
    has_ssl: bool


class DomainsResponse(BaseModel):
    """List of domains response."""
    domains: list[DomainInfo]


@router.post("/connect", response_model=ConnectResponse, dependencies=[Depends(require_csrf)])
async def connect(request: ConnectRequest) -> ConnectResponse:
    """Establish SSH connection to a server.
    
    Returns a host_id (session token) for subsequent API calls.
    """
    config = SSHConfig(
        host=request.host,
        user=request.username,
        port=request.port,
        key_path=request.key_path,
        passphrase=request.key_passphrase,
        password=request.password,
        use_sudo=True,
    )
    
    try:
        session_id = session_store.create_session(config)
        
        # Get basic server info
        session = session_store.get_session(session_id)
        if not session:
            raise HTTPException(status_code=500, detail="Session creation failed")
        
        ssh = session.ssh
        
        # Get OS info
        os_result = ssh.run("cat /etc/os-release | grep PRETTY_NAME | cut -d'\"' -f2")
        os_name = os_result.stdout.strip() if os_result.success else "Unknown"
        
        # Get Nginx version
        nginx_result = ssh.run("nginx -v 2>&1")
        nginx_version = "Not found"
        if nginx_result.success or "nginx version" in nginx_result.stderr:
            version_text = nginx_result.stderr or nginx_result.stdout
            if "nginx/" in version_text:
                nginx_version = version_text.split("nginx/")[1].split()[0].strip()
        
        return ConnectResponse(
            host_id=session_id,
            os_name=os_name,
            nginx_version=nginx_version,
        )
        
    except ConnectionError as e:
        raise HTTPException(status_code=401, detail=str(e))
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Connection failed: {str(e)}")


@router.get("/domains", response_model=DomainsResponse)
async def list_domains(host_id: str) -> DomainsResponse:
    """List Nginx domains from server configuration."""
    session = session_store.get_session(host_id)
    if not session:
        raise HTTPException(status_code=401, detail="Invalid or expired session")
    
    ssh = session.ssh
    
    try:
        # Use NginxScanner to parse config
        scanner = NginxScanner(ssh)
        nginx_info = scanner.scan()
        
        domains: list[DomainInfo] = []
        seen = set()
        
        for server in nginx_info.servers:
            for name in server.server_names:
                # Skip wildcards and defaults
                if name.startswith("_") or name.startswith("*") or name in seen:
                    continue
                seen.add(name)
                
                domains.append(DomainInfo(
                    domain=name,
                    source_file=server.source_file,
                    has_ssl=bool(server.ssl_certificate),
                ))
        
        return DomainsResponse(domains=domains)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to list domains: {str(e)}")
