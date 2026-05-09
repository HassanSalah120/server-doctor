"""Tests for Security Auditor."""

import sys
from pathlib import Path
from unittest.mock import MagicMock

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from server_doctor.checks.security.security_auditor import SecurityAuditor
from server_doctor.model.server import ServerModel, NginxInfo, ServerBlock, LocationBlock
from server_doctor.model.evidence import Severity
from server_doctor.checks import CheckContext

def test_security_audit_findings():
    """Verify security auditors detect missing headers and bad configs."""
    auditor = SecurityAuditor()
    
    # Mock Nginx Config
    server = ServerBlock(
        server_names=["example.com"],
        listen=["80"],
        autoindex=True, # Should trigger NGX-SEC-2
        headers={"X-XSS-Protection": "1; mode=block"}
    )
    
    # Missing: Content-Security-Policy, Strict-Transport-Security, X-Content-Type-Options
    # These should trigger SEC-HEAD-1
    
    # NGX-SEC-3: Dotfile protection missing (no location matching \.)
    # The server setup below does NOT have a dotfile location, so NGX-SEC-3 SHOULD be in ids.
    
    # Actually, let's just use what the auditor expects.
    # SEC-HEAD-1: Missing headers
    # NGX-SEC-2: autoindex on
    # NGX-SEC-3: Dotfile protection missing (no location matching \.)
    # NGX-SEC-4: PHP in uploads (location /uploads { location ~ \.php })
    
    loc_uploads = LocationBlock(path="/uploads", source_file="/etc/nginx/nginx.conf")
    loc_php = LocationBlock(path="~ \\.php$", source_file="/etc/nginx/nginx.conf")
    loc_php.fastcgi_pass = "unix:/run/php/php-fpm.sock"
    loc_uploads.locations = [loc_php]
    
    server.locations = [loc_uploads]
    
    nginx_info = NginxInfo(version="1.18", config_path="/etc/nginx/nginx.conf")
    nginx_info.servers = [server]
    
    model = ServerModel(hostname="test")
    model.nginx = nginx_info
    
    ctx = CheckContext(model=model, ssh=None)
    
    findings = auditor.run(ctx)
    ids = [f.id for f in findings]
    print(f"DEBUG_IDS: {ids}")
    
    print(f"Findings: {ids}")
    # Verify expected IDs
    assert 'SEC-HEAD-1' in ids # Missing headers
    assert 'NGX-SEC-2' in ids     # Autoindex enabled
    assert 'NGX-SEC-3' in ids     # Dotfile protection missing
    assert 'NGX-SEC-4' in ids     # PHP in uploads

    # sensitive path detection
    # add an admin location on same server
    server.locations.append(LocationBlock(path="/admin", source_file="/etc/nginx/nginx.conf"))
    findings = auditor.run(ctx)
    ids = [f.id for f in findings]
    assert 'NGX-SENS-1' in ids

    # default_server with sensitive path should be critical
    default_srv = ServerBlock(server_names=["_"], listen=["80 default_server"])
    default_srv.locations = [LocationBlock(path="/admin", source_file="/etc/nginx/nginx.conf")]
    nginx_info.servers.append(default_srv)
    findings = auditor.run(ctx)
    sens_findings = [f for f in findings if f.id == 'NGX-SENS-1']
    assert any(f.severity == Severity.CRITICAL for f in sens_findings)


def test_sensitive_admin_path_with_ip_allowlist_is_not_flagged():
    """NGX-SENS-1 should not fire when /admin is explicitly IP-restricted."""
    auditor = SecurityAuditor()

    admin_loc = LocationBlock(
        path="/admin/",
        source_file="/etc/nginx/conf.d/default.conf",
        line_number=100,
        allow_rules=["127.0.0.1", "::1"],
        deny_rules=["all"],
    )
    server = ServerBlock(
        server_names=["vote.schmobinquiz.de"],
        listen=["443 ssl"],
        locations=[admin_loc],
        source_file="/etc/nginx/conf.d/default.conf",
        line_number=1,
    )
    model = ServerModel(
        hostname="vote.schmobinquiz.de",
        nginx=NginxInfo(
            version="1.29.3",
            config_path="/etc/nginx/nginx.conf",
            servers=[server],
        ),
    )
    ctx = CheckContext(model=model, ssh=None)

    findings = auditor.run(ctx)
    assert "NGX-SENS-1" not in {f.id for f in findings}


def test_sensitive_admin_path_inherits_server_access_rules():
    """NGX-SENS-1 should not fire when server-level allow/deny already restricts access."""
    auditor = SecurityAuditor()

    admin_loc = LocationBlock(
        path="/admin/",
        source_file="/etc/nginx/conf.d/default.conf",
        line_number=120,
    )
    server = ServerBlock(
        server_names=["vote.schmobinquiz.de"],
        listen=["443 ssl"],
        locations=[admin_loc],
        allow_rules=["127.0.0.1", "::1"],
        deny_rules=["all"],
        source_file="/etc/nginx/conf.d/default.conf",
        line_number=1,
    )
    model = ServerModel(
        hostname="vote.schmobinquiz.de",
        nginx=NginxInfo(
            version="1.29.3",
            config_path="/etc/nginx/nginx.conf",
            servers=[server],
        ),
    )
    ctx = CheckContext(model=model, ssh=None)

    findings = auditor.run(ctx)
    assert "NGX-SENS-1" not in {f.id for f in findings}


def test_sensitive_admin_path_with_include_allow_deny_is_not_flagged():
    """NGX-SENS-1 should not fire when allow/deny are provided through include files."""
    auditor = SecurityAuditor()

    admin_loc = LocationBlock(
        path="/admin/",
        source_file="/etc/nginx/conf.d/default.conf",
        line_number=130,
        include_files=["/etc/nginx/conf.d/admin_acl.inc"],
    )
    server = ServerBlock(
        server_names=["localhost"],
        listen=["443 ssl"],
        locations=[admin_loc],
        source_file="/etc/nginx/conf.d/default.conf",
        line_number=1,
    )
    nginx = NginxInfo(
        version="1.29.3",
        config_path="/etc/nginx/nginx.conf",
        servers=[server],
    )
    nginx.virtual_files["/etc/nginx/conf.d/admin_acl.inc"] = """
allow 127.0.0.1;
allow ::1;
deny all;
"""

    model = ServerModel(hostname="localhost", nginx=nginx)
    ctx = CheckContext(model=model, ssh=None)

    findings = auditor.run(ctx)
    assert "NGX-SENS-1" not in {f.id for f in findings}


def test_sensitive_admin_path_with_auth_basic_is_not_flagged():
    """NGX-SENS-1 should not fire when location is protected by basic auth."""
    auditor = SecurityAuditor()

    admin_loc = LocationBlock(
        path="/admin/",
        source_file="/etc/nginx/conf.d/default.conf",
        line_number=140,
        auth_basic='"Restricted"',
    )
    server = ServerBlock(
        server_names=["vote.schmobinquiz.de"],
        listen=["443 ssl"],
        locations=[admin_loc],
        source_file="/etc/nginx/conf.d/default.conf",
        line_number=1,
    )
    model = ServerModel(
        hostname="vote.schmobinquiz.de",
        nginx=NginxInfo(
            version="1.29.3",
            config_path="/etc/nginx/nginx.conf",
            servers=[server],
        ),
    )
    ctx = CheckContext(model=model, ssh=None)

    findings = auditor.run(ctx)
    assert "NGX-SENS-1" not in {f.id for f in findings}


def test_security_headers_from_include_are_respected():
    """SEC-HEAD-1 should account for add_header directives in included files."""
    auditor = SecurityAuditor()

    health_loc = LocationBlock(
        path="/health",
        source_file="/etc/nginx/conf.d/default.conf",
        line_number=200,
        headers={"Content-Type": "text/plain"},
        include_files=["/etc/nginx/conf.d/security_headers.inc"],
    )
    server = ServerBlock(
        server_names=["vote.schmobinquiz.de"],
        listen=["443 ssl"],
        locations=[health_loc],
        source_file="/etc/nginx/conf.d/default.conf",
        line_number=1,
    )
    nginx = NginxInfo(
        version="1.29.3",
        config_path="/etc/nginx/nginx.conf",
        servers=[server],
    )
    nginx.virtual_files["/etc/nginx/conf.d/security_headers.inc"] = """
add_header X-Frame-Options "DENY" always;
add_header X-Content-Type-Options "nosniff" always;
add_header Referrer-Policy "strict-origin-when-cross-origin" always;
"""

    model = ServerModel(hostname="vote.schmobinquiz.de", nginx=nginx)
    ctx = CheckContext(model=model, ssh=None)

    findings = auditor.run(ctx)
    assert "SEC-HEAD-1" not in {f.id for f in findings}


def test_security_headers_respect_add_header_inherit_merge():
    """SEC-HEAD-1 should not fire when location uses add_header_inherit merge."""
    auditor = SecurityAuditor()

    health_loc = LocationBlock(
        path="/health",
        source_file="/etc/nginx/conf.d/default.conf",
        line_number=210,
        headers={"Content-Type": "text/plain"},
        add_header_inherit="merge",
    )
    server = ServerBlock(
        server_names=["vote.schmobinquiz.de"],
        listen=["443 ssl"],
        headers={
            "X-Frame-Options": '"DENY" always',
            "X-Content-Type-Options": '"nosniff" always',
            "Referrer-Policy": '"strict-origin-when-cross-origin" always',
        },
        locations=[health_loc],
        source_file="/etc/nginx/conf.d/default.conf",
        line_number=1,
    )
    nginx = NginxInfo(
        version="1.29.3",
        config_path="/etc/nginx/nginx.conf",
        servers=[server],
    )

    model = ServerModel(hostname="vote.schmobinquiz.de", nginx=nginx)
    ctx = CheckContext(model=model, ssh=None)

    findings = auditor.run(ctx)
    assert "SEC-HEAD-1" not in {f.id for f in findings}
