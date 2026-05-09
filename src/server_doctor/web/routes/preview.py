"""
Preview API routes.

Endpoint:
- POST /api/preview-setup - Generate config preview (dry-run)
"""

from typing import Optional
from pydantic import BaseModel, Field

from fastapi import APIRouter, Depends, HTTPException

from server_doctor.web.session import session_store
from server_doctor.web.snippets import (
    generate_laravel_location,
    generate_static_location,
    generate_proxy_location,
    generate_websocket_location,
    generate_laravel_checklist,
    check_existing_marker,
)
from server_doctor.web.detection import (
    detect_apache_proxy,
    generate_apache_laravel_snippet,
    generate_apache_instructions,
    ApacheProxyInfo,
)
from server_doctor.scanner.nginx import NginxScanner
from server_doctor.web.security import require_auth, require_csrf


router = APIRouter(dependencies=[Depends(require_auth)])


class WebSocketConfig(BaseModel):
    """WebSocket proxy configuration."""
    enabled: bool = False
    path: Optional[str] = None  # e.g., /chat-duel/socket.io/
    target: Optional[str] = None  # e.g., http://127.0.0.1:8099


class PreviewRequest(BaseModel):
    """Preview setup request."""
    host_id: str = Field(..., description="Session ID from connect")
    domain: str = Field(..., description="Target domain (e.g., schmobinquiz.de)")
    path: str = Field(..., description="URL path (must start with /)")
    project_type: str = Field(..., description="laravel | static | proxy")
    root: Optional[str] = Field(None, description="Filesystem root (required for laravel/static)")
    php_version: str = Field("auto", description="PHP version: auto | 8.2 | 8.3 | 8.4")
    fpm_socket: str = Field("auto", description="PHP-FPM socket: auto | custom path")
    proxy_target: Optional[str] = Field(None, description="For proxy type: backend URL")
    websocket: Optional[WebSocketConfig] = None


class ValidationResult(BaseModel):
    """Validation check result."""
    path_exists: bool = Field(..., description="Path already exists in config")
    root_overlap: bool = Field(..., description="Root overlaps with existing project")
    marker_exists: bool = Field(..., description="server-doctor marker already exists")
    fpm_socket_detected: str = Field(..., description="Detected PHP-FPM socket")


class InsertionPlan(BaseModel):
    """Where to insert the snippet."""
    file: str
    server_block: str
    position: str


class ApacheProxyDetection(BaseModel):
    """Apache proxy detection result."""
    detected: bool = False
    proxy_port: Optional[int] = None
    config_path: str = "/etc/apache2/sites-enabled/000-default.conf"
    instructions: list[str] = []


class PreviewResponse(BaseModel):
    """Preview response."""
    nginx_file: str
    validation: ValidationResult
    nginx_snippet: str
    websocket_snippet: Optional[str] = None
    insertion_plan: InsertionPlan
    checklist: list[str]
    warnings: list[str]
    # Apache proxy detection
    apache_proxy: Optional[ApacheProxyDetection] = None
    apache_snippet: Optional[str] = None


def detect_fpm_socket(ssh: any, php_version: str = "auto") -> str:
    """Detect PHP-FPM socket path from server.
    
    Args:
        ssh: SSH connector.
        php_version: Preferred version or "auto".
        
    Returns:
        Socket path.
    """
    # Common socket locations
    socket_patterns = [
        "/run/php/php{version}-fpm.sock",
        "/var/run/php/php{version}-fpm.sock",
        "/var/run/php-fpm/www.sock",
    ]
    
    # Try to detect installed PHP versions
    result = ssh.run("ls -1 /run/php/ 2>/dev/null | grep -oP 'php\\K[0-9]+\\.[0-9]+' | sort -V | tail -1")
    if result.success and result.stdout.strip():
        detected_version = result.stdout.strip()
    else:
        detected_version = "8.2"  # fallback
    
    version = detected_version if php_version == "auto" else php_version
    
    for pattern in socket_patterns:
        socket_path = pattern.format(version=version)
        if ssh.file_exists(socket_path):
            return socket_path
    
    # Fallback
    return f"/run/php/php{version}-fpm.sock"


def find_server_block_file(nginx_info: any, domain: str) -> tuple[str, any]:
    """Find the config file containing the server block for a domain.
    
    Args:
        nginx_info: NginxInfo from scanner.
        domain: Domain to find.
        
    Returns:
        Tuple of (file_path, server_block) or raises HTTPException.
    """
    for server in nginx_info.servers:
        if domain in server.server_names:
            return server.source_file, server
    
    raise HTTPException(
        status_code=404,
        detail=f"No server block found for domain: {domain}"
    )


def check_existing_location(config_content: str, path: str) -> bool:
    """Check if a location block for this path already exists.
    
    Args:
        config_content: Nginx config file content.
        path: Path to check (e.g., /chat-duel).
        
    Returns:
        True if location already exists.
    """
    import re
    path_normalized = "/" + path.strip("/")
    # Match location blocks: location /path { or location = /path {
    pattern = rf'location\s+[~=^]*\s*{re.escape(path_normalized)}\s*\{{'
    return bool(re.search(pattern, config_content))


@router.post("/preview-setup", response_model=PreviewResponse, dependencies=[Depends(require_csrf)])
async def preview_setup(request: PreviewRequest) -> PreviewResponse:
    """Generate config preview (dry-run).
    
    Validates configuration and generates Nginx snippets without applying.
    """
    session = session_store.get_session(request.host_id)
    if not session:
        raise HTTPException(status_code=401, detail="Invalid or expired session")
    
    ssh = session.ssh
    
    try:
        warnings: list[str] = []
        
        # Validate path format
        if not request.path.startswith("/"):
            request.path = "/" + request.path
        
        # Validate project type
        if request.project_type == "laravel" and not request.root:
            raise HTTPException(status_code=400, detail="Root is required for Laravel projects")
        if request.project_type == "static" and not request.root:
            raise HTTPException(status_code=400, detail="Root is required for static projects")
        if request.project_type == "proxy" and not request.proxy_target:
            raise HTTPException(status_code=400, detail="Proxy target is required for proxy projects")
        
        # Find server block
        scanner = NginxScanner(ssh)
        nginx_info = scanner.scan()
        source_file, server_block = find_server_block_file(nginx_info, request.domain)
        
        # Read config file
        config_content = ssh.read_file(source_file) or ""
        
        # Validation checks
        path_exists = check_existing_location(config_content, request.path)
        marker_exists = check_existing_marker(config_content, request.path)
        
        if path_exists:
            warnings.append(f"Location {request.path} already exists in config")
        if marker_exists:
            warnings.append(f"server-doctor project marker for {request.path} already exists - duplicate insertion prevented")
        
        # Check root overlap (basic check)
        root_overlap = False
        if request.root:
            for server in nginx_info.servers:
                if server.root and request.root.startswith(server.root):
                    if server.root != request.root:
                        root_overlap = True
                        warnings.append(f"Root {request.root} may overlap with existing root {server.root}")
        
        # Detect FPM socket
        if request.project_type == "laravel":
            fpm_socket = request.fpm_socket
            if fpm_socket == "auto":
                fpm_socket = detect_fpm_socket(ssh, request.php_version)
            
            if not ssh.file_exists(fpm_socket):
                warnings.append(f"PHP-FPM socket not found at {fpm_socket}")
        else:
            fpm_socket = ""
        
        # Generate snippet
        if request.project_type == "laravel":
            nginx_snippet = generate_laravel_location(
                path=request.path,
                root=request.root,  # type: ignore
                fpm_socket=fpm_socket,
                php_version=request.php_version,
            )
        elif request.project_type == "static":
            nginx_snippet = generate_static_location(
                path=request.path,
                root=request.root,  # type: ignore
            )
        elif request.project_type == "proxy":
            nginx_snippet = generate_proxy_location(
                path=request.path,
                proxy_target=request.proxy_target,  # type: ignore
            )
        else:
            raise HTTPException(status_code=400, detail=f"Unknown project type: {request.project_type}")
        
        # Generate WebSocket snippet if enabled
        websocket_snippet = None
        if request.websocket and request.websocket.enabled:
            if request.websocket.path and request.websocket.target:
                websocket_snippet = generate_websocket_location(
                    path=request.websocket.path,
                    proxy_target=request.websocket.target,
                )
        
        # Generate checklist
        if request.project_type == "laravel" and request.root:
            checklist = generate_laravel_checklist(request.path, request.root)
        else:
            checklist = []
        
        # Detect Apache proxy architecture
        apache_proxy_result = None
        apache_snippet_result = None
        
        apache_info = detect_apache_proxy(nginx_info)
        if apache_info and apache_info.detected:
            # Server uses Nginx→Apache proxy architecture
            if request.project_type == "laravel":
                warnings.insert(0, f"⚠️ APACHE PROXY DETECTED: This server proxies PHP requests to Apache on port {apache_info.proxy_port}. "
                                  f"The Nginx snippet below will NOT work. Use the Apache configuration instead.")
                
                apache_snippet_result = generate_apache_laravel_snippet(
                    path=request.path,
                    root=request.root,  # type: ignore
                )
                
                apache_proxy_result = ApacheProxyDetection(
                    detected=True,
                    proxy_port=apache_info.proxy_port,
                    config_path=apache_info.apache_config_path,
                    instructions=generate_apache_instructions(
                        path=request.path,
                        root=request.root,  # type: ignore
                    ),
                )
        
        return PreviewResponse(
            nginx_file=source_file,
            validation=ValidationResult(
                path_exists=path_exists,
                root_overlap=root_overlap,
                marker_exists=marker_exists,
                fpm_socket_detected=fpm_socket,
            ),
            nginx_snippet=nginx_snippet,
            websocket_snippet=websocket_snippet,
            insertion_plan=InsertionPlan(
                file=source_file,
                server_block=f"server {{ server_name {request.domain}; ... }}",
                position="Before closing brace of server block",
            ),
            checklist=checklist,
            warnings=warnings,
            apache_proxy=apache_proxy_result,
            apache_snippet=apache_snippet_result,
        )
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Preview failed: {str(e)}")
