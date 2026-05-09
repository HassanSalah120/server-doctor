"""Tests for Laravel Auditor."""

import sys
from pathlib import Path
from unittest.mock import MagicMock

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from server_doctor.checks.laravel.laravel_auditor import LaravelAuditor
from server_doctor.model.server import ServerModel, ProjectInfo, ProjectType

def test_laravel_detection_and_finding():
    """Verify Laravel detection logic and finding generation."""
    auditor = LaravelAuditor()
    server = ServerModel(hostname="test")
    
    # Mock project
    p = ProjectInfo(path="/var/www/laravel", type=ProjectType.LARAVEL, confidence=1.0)
    
    # Mock Scan results on project (mocking files in check context relies on Auditor internals)
    # LaravelAuditor uses server.projects and then ssh.file_exists or read_file via check logic
    # But checks are implemented in scan_project
    
    # We'll mock the internal `_check_app_debug` etc if needed, or pass a CheckContext
    # The current audit() method signature takes (model, check_ctx).
    
    # Let's mock CheckContext
    ctx = MagicMock()
    ctx.model = server
    ctx.laravel_enabled = True
    
    # Mock SSH interactions
    def ssh_side_effect(cmd):
        if "grep -E '^APP_DEBUG='" in cmd:
            return MagicMock(stdout="APP_DEBUG=true\n")
        if "grep -E '^APP_ENV='" in cmd:
            return MagicMock(stdout="APP_ENV=production\n")
        if "test -f" in cmd and "artisan" in cmd:
            return MagicMock(stdout="yes")
        if "test -f" in cmd and ".env" in cmd:
            return MagicMock(stdout="yes")
        if "test -w" in cmd and "storage" in cmd:
            return MagicMock(stdout="no") # Simulate write failure
        if "test -w" in cmd and "bootstrap/cache" in cmd:
            return MagicMock(stdout="no")
        return MagicMock(stdout="")

    ctx.ssh.run.side_effect = ssh_side_effect
    ctx.ssh.file_exists.return_value = True

    # Add project to model
    server.projects.append(p)
    
    findings = auditor.run(ctx)
    
    # Should find LARAVEL-1 (Debug enabled) and permissions warnings
    ids = [f.id for f in findings]
    assert "LARAVEL-1" in ids
    assert "LARAVEL-2" in ids
    assert "LARAVEL-3" in ids
