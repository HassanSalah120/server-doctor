"""
Server architecture detection module.

Detects server setups like:
- Nginx → Apache proxy (PHP apps served via Apache)
- Nginx direct (PHP-FPM)
- Nginx → Node.js proxy
"""

import re
from dataclasses import dataclass
from typing import TYPE_CHECKING, Optional

if TYPE_CHECKING:
    from server_doctor.parser.nginx_conf import NginxInfo


@dataclass
class ApacheProxyInfo:
    """Information about detected Apache proxy setup."""
    detected: bool
    proxy_port: int
    proxy_location: str  # e.g., "location /" or "location ~ \\.php$"
    evidence_file: str
    evidence_line: int
    
    @property
    def apache_config_path(self) -> str:
        """Likely Apache config path."""
        return "/etc/apache2/sites-enabled/000-default.conf"


# Common ports used by Apache when behind Nginx
APACHE_BACKEND_PORTS = [8000, 8080, 8100, 8888]


def detect_apache_proxy(nginx_info: "NginxInfo") -> Optional[ApacheProxyInfo]:
    """Detect if server uses Nginx→Apache proxy architecture.
    
    This architecture is common when:
    - Nginx handles SSL termination and static files
    - Apache handles PHP via mod_php (instead of PHP-FPM)
    - Nginx has a catch-all proxy_pass to Apache
    
    Args:
        nginx_info: Parsed Nginx configuration.
        
    Returns:
        ApacheProxyInfo if detected, None otherwise.
    """
    for server in nginx_info.servers:
        for location in server.locations:
            # Check for catch-all locations that proxy to Apache
            if not location.proxy_pass:
                continue
            
            proxy_url = location.proxy_pass
            
            # Check if proxying to localhost on Apache-typical ports
            for port in APACHE_BACKEND_PORTS:
                patterns = [
                    f"http://127.0.0.1:{port}",
                    f"http://localhost:{port}",
                ]
                
                for pattern in patterns:
                    if proxy_url.startswith(pattern):
                        # Found Apache proxy!
                        return ApacheProxyInfo(
                            detected=True,
                            proxy_port=port,
                            proxy_location=location.path,
                            evidence_file=location.source_file or server.source_file,
                            evidence_line=location.line_number,
                        )
    
    return None


def generate_apache_laravel_snippet(
    path: str,
    root: str,
) -> str:
    """Generate Apache configuration snippet for Laravel under subpath.
    
    Args:
        path: URL path (e.g., /chat-duel).
        root: Filesystem root (e.g., /var/www/chat-duel).
        
    Returns:
        Apache Alias and Directory configuration.
    """
    path = "/" + path.strip("/")
    root = root.rstrip("/")
    
    return f'''        # {path.strip('/')} Laravel app
        Alias {path}/ {root}/public/
        RedirectMatch 301 ^{path}$ {path}/

        <Directory {root}/public/>
            AllowOverride All
            Require all granted
            Options -Indexes +FollowSymLinks
            DirectoryIndex index.php
            DirectorySlash Off

            <IfModule mod_rewrite.c>
                RewriteEngine On
                RewriteBase {path}/
                RewriteCond %{{REQUEST_FILENAME}} !-f
                RewriteCond %{{REQUEST_FILENAME}} !-d
                RewriteRule ^ index.php [L]
            </IfModule>
        </Directory>'''


def generate_apache_instructions(
    path: str,
    root: str,
    apache_config: str = "/etc/apache2/sites-enabled/000-default.conf",
) -> list[str]:
    """Generate manual instructions for Apache configuration.
    
    Args:
        path: URL path.
        root: Filesystem root.
        apache_config: Apache config file path.
        
    Returns:
        List of instruction steps.
    """
    return [
        f"1. Open Apache config: sudo nano {apache_config}",
        f"2. Add the Alias and Directory block (shown below) inside <VirtualHost>",
        f"3. Save and test: sudo apache2ctl configtest",
        f"4. Reload Apache: sudo systemctl reload apache2",
        f"5. Verify: curl -I https://yourdomain.com{path}/",
    ]
