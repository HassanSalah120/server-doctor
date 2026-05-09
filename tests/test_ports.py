"""Tests for Port Usage Auditor."""

import sys
from pathlib import Path
from unittest.mock import MagicMock

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from server_doctor.checks.ports.port_auditor import PortAuditor
from server_doctor.checks.ports.port_auditor import PortAuditor
from server_doctor.model.server import ServerModel, NginxInfo, LocationBlock, ServerBlock

def test_port_checks():
    """Verify dead proxy target detection."""
    auditor = PortAuditor()
    ctx = MagicMock()
    
    # Mock Netstat/SS output
    # Local listeners: 80, 22
    ctx.ssh.execute.return_value = (0, "tcp 0 0 0.0.0.0:80 LISTEN ...\ntcp 0 0 0.0.0.0:22 LISTEN ...", "")
    
    # Mock Nginx Config
    server = ServerModel(hostname="test")
    nginx = NginxInfo(version="1.18", config_path="/etc/nginx/nginx.conf")
    server.nginx = nginx
    
    # Location proxying to 8080 (which is NOT listening)
    # PORT-1 should be triggered
    loc = LocationBlock(path="/api", source_file="/etc/nginx/sites-enabled/default")
    loc.line_number = 10
    loc.directives = {"proxy_pass": "http://127.0.0.1:8080"}
    loc.proxy_pass = "http://127.0.0.1:8080"

    srv_obj = ServerBlock(
        server_names=["example.com"],
        listen=["8080"],
        source_file="/etc/nginx/sites-enabled/default",
        line_number=1
    )
    srv_obj.locations = [loc]
    nginx.servers = [srv_obj]
    
    ctx.model = server
    ctx.ports_enabled = True
    
    findings = auditor.run(ctx)
    
    ids = [f.id for f in findings]
    assert "PORT-1" in ids # Proxy to dead port
