"""
Nginx config snippet generator for Laravel subpath projects.

Generates:
- Laravel location blocks with proper PHP-FPM routing
- WebSocket proxy blocks
- Idempotency markers to prevent duplicate insertion
"""

from typing import Optional
from datetime import datetime


# Idempotency marker format
MARKER_START = "# --- server-doctor project: {path} ({type}) ---"
MARKER_END = "# --- end server-doctor project: {path} ---"


def generate_marker_start(path: str, project_type: str) -> str:
    """Generate start marker for idempotent insertion."""
    return MARKER_START.format(path=path, type=project_type)


def generate_marker_end(path: str) -> str:
    """Generate end marker for idempotent insertion."""
    return MARKER_END.format(path=path)


def check_existing_marker(config_content: str, path: str) -> bool:
    """Check if project marker already exists in config.
    
    Args:
        config_content: Nginx config file content.
        path: Project path to check.
        
    Returns:
        True if marker exists (duplicate would be inserted).
    """
    marker = f"server-doctor project: {path}"
    return marker in config_content


def generate_laravel_location(
    path: str,
    root: str,
    fpm_socket: str,
    php_version: str = "8.2",
) -> str:
    """Generate Nginx location block for Laravel under subpath.
    
    Args:
        path: URL path (e.g., /chat-duel).
        root: Filesystem root (e.g., /var/www/chat-duel).
        fpm_socket: PHP-FPM socket path.
        php_version: PHP version for socket detection.
        
    Returns:
        Nginx location block configuration.
    """
    # Ensure path starts with / and has no trailing slash
    path = "/" + path.strip("/")
    root = root.rstrip("/")
    public_root = f"{root}/public"
    
    snippet = f'''
{generate_marker_start(path, "laravel")}
location {path} {{
    alias {public_root};
    index index.php;
    try_files $uri $uri/ @{path.strip("/")}_laravel;
}}

location @{path.strip("/")}_laravel {{
    rewrite ^{path}/(.*)$ {path}/index.php?/$1 last;
}}

location ~ ^{path}/index\\.php(/|$) {{
    alias {public_root};
    fastcgi_pass unix:{fpm_socket};
    fastcgi_split_path_info ^({path})(/.*)$;
    fastcgi_param SCRIPT_FILENAME {public_root}/index.php;
    fastcgi_param PATH_INFO $fastcgi_path_info;
    include fastcgi_params;
    fastcgi_param REQUEST_URI $request_uri;
}}

location ~ ^{path}/.*\\.php$ {{
    deny all;
    return 404;
}}
{generate_marker_end(path)}
'''
    return snippet.strip()


def generate_static_location(
    path: str,
    root: str,
) -> str:
    """Generate Nginx location block for static files.
    
    Args:
        path: URL path (e.g., /docs).
        root: Filesystem root for static files.
        
    Returns:
        Nginx location block configuration.
    """
    path = "/" + path.strip("/")
    root = root.rstrip("/")
    
    snippet = f'''
{generate_marker_start(path, "static")}
location {path} {{
    alias {root};
    index index.html;
    try_files $uri $uri/ =404;
    
    # Cache static assets
    location ~* \\.(css|js|png|jpg|jpeg|gif|ico|svg|woff|woff2)$ {{
        expires 30d;
        add_header Cache-Control "public, immutable";
    }}
}}
{generate_marker_end(path)}
'''
    return snippet.strip()


def generate_proxy_location(
    path: str,
    proxy_target: str,
) -> str:
    """Generate Nginx location block for reverse proxy.
    
    Args:
        path: URL path (e.g., /api).
        proxy_target: Backend URL (e.g., http://127.0.0.1:3000).
        
    Returns:
        Nginx location block configuration.
    """
    path = "/" + path.strip("/")
    
    snippet = f'''
{generate_marker_start(path, "proxy")}
location {path} {{
    proxy_pass {proxy_target};
    proxy_http_version 1.1;
    proxy_set_header Host $host;
    proxy_set_header X-Real-IP $remote_addr;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto $scheme;
}}
{generate_marker_end(path)}
'''
    return snippet.strip()


def generate_websocket_location(
    path: str,
    proxy_target: str,
) -> str:
    """Generate Nginx location block for WebSocket proxy.
    
    Args:
        path: WebSocket path (e.g., /chat-duel/socket.io/).
        proxy_target: Backend WebSocket URL (e.g., http://127.0.0.1:8099).
        
    Returns:
        Nginx location block configuration.
    """
    path = "/" + path.strip("/")
    if not path.endswith("/"):
        path += "/"
    
    snippet = f'''
{generate_marker_start(path, "websocket")}
location {path} {{
    proxy_pass {proxy_target};
    proxy_http_version 1.1;
    proxy_set_header Upgrade $http_upgrade;
    proxy_set_header Connection "upgrade";
    proxy_set_header Host $host;
    proxy_set_header X-Real-IP $remote_addr;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto $scheme;
    proxy_read_timeout 86400;
}}
{generate_marker_end(path)}
'''
    return snippet.strip()


def generate_laravel_checklist(path: str, root: str) -> list[str]:
    """Generate Laravel deployment checklist.
    
    Args:
        path: Project URL path.
        root: Filesystem root.
        
    Returns:
        List of checklist items.
    """
    return [
        f"cd {root}",
        "composer install --no-dev --optimize-autoloader",
        "cp .env.example .env && php artisan key:generate",
        "php artisan migrate --force",
        "php artisan config:cache",
        "php artisan route:cache",
        "php artisan view:cache",
        f"chown -R www-data:www-data {root}/storage {root}/bootstrap/cache",
        f"chmod -R 775 {root}/storage {root}/bootstrap/cache",
    ]
