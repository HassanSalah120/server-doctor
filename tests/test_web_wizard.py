"""
Tests for Web Wizard snippet generation and safe apply.

Covers:
- Preview generates correct snippet
- Apply performs backup + rollback on nginx -t failure
- No secret leakage in logs
- Idempotent marker detection
"""

import pytest
from pathlib import Path
from unittest.mock import MagicMock, patch
from datetime import datetime

from server_doctor.web.snippets import (
    generate_laravel_location,
    generate_websocket_location,
    check_existing_marker,
    generate_marker_start,
    generate_marker_end,
)
from server_doctor.web.safe_apply import (
    find_server_block_end,
    insert_snippet_in_server_block,
    create_backup_path,
)
from server_doctor.web.jobs import Job, JobStatus


# Fixture path
FIXTURE_DIR = Path(__file__).parent / "fixtures" / "web_wizard"


class TestSnippetGeneration:
    """Test Nginx snippet generation."""
    
    def test_laravel_snippet_has_markers(self):
        """Laravel snippet must have idempotency markers."""
        snippet = generate_laravel_location(
            path="/chat-duel",
            root="/var/www/chat-duel",
            fpm_socket="/run/php/php8.2-fpm.sock",
        )
        
        assert "server-doctor project: /chat-duel (laravel)" in snippet
        assert "end server-doctor project: /chat-duel" in snippet
    
    def test_laravel_snippet_correct_structure(self):
        """Laravel snippet must have correct location block structure."""
        snippet = generate_laravel_location(
            path="/chat-duel",
            root="/var/www/chat-duel",
            fpm_socket="/run/php/php8.2-fpm.sock",
        )
        
        # Must have main location
        assert "location /chat-duel {" in snippet
        # Must have alias to public
        assert "alias /var/www/chat-duel/public" in snippet
        # Must have fastcgi_pass
        assert "fastcgi_pass unix:/run/php/php8.2-fpm.sock" in snippet
        # Must have SCRIPT_FILENAME
        assert "SCRIPT_FILENAME" in snippet
    
    def test_websocket_snippet_has_upgrade_headers(self):
        """WebSocket snippet must have upgrade headers."""
        snippet = generate_websocket_location(
            path="/chat-duel/socket.io/",
            proxy_target="http://127.0.0.1:8099",
        )
        
        assert 'Upgrade $http_upgrade' in snippet
        assert 'Connection "upgrade"' in snippet
        assert "proxy_pass http://127.0.0.1:8099" in snippet
    
    def test_check_existing_marker_detects_duplicate(self):
        """Must detect existing markers to prevent duplicates."""
        config = """
        # --- server-doctor project: /wcas (laravel) ---
        location /wcas { ... }
        # --- end server-doctor project: /wcas ---
        """
        
        assert check_existing_marker(config, "/wcas") is True
        assert check_existing_marker(config, "/chat-duel") is False


class TestServerBlockParsing:
    """Test server block detection and insertion."""
    
    def test_find_server_block_end(self):
        """Must find correct closing brace for server block."""
        config = """
server {
    listen 80;
    server_name example.com;
    
    location / {
        root /var/www;
    }
}
"""
        pos = find_server_block_end(config, "example.com")
        assert pos is not None
        assert config[pos] == "}"
    
    def test_insert_snippet_in_server_block(self):
        """Must insert snippet before closing brace."""
        config = """server {
    server_name example.com;
    location / { }
}"""
        snippet = "location /test { }"
        
        result = insert_snippet_in_server_block(config, "example.com", snippet)
        
        assert result is not None
        assert "location /test { }" in result
        # Snippet should be before final }
        assert result.index("location /test") < result.rindex("}")
    
    def test_insert_with_real_fixture(self):
        """Test insertion with real fixture config."""
        config_path = FIXTURE_DIR / "schmobinquiz.de.conf"
        if not config_path.exists():
            pytest.skip("Fixture not found")
        
        config = config_path.read_text()
        
        snippet = generate_laravel_location(
            path="/chat-duel",
            root="/var/www/chat-duel",
            fpm_socket="/run/php/php8.2-fpm.sock",
        )
        
        result = insert_snippet_in_server_block(config, "schmobinquiz.de", snippet)
        
        assert result is not None
        assert "/chat-duel" in result
        # Original locations still present
        assert "/wcas" in result
        assert "/imposter" in result


class TestBackupPath:
    """Test backup path generation."""
    
    def test_backup_path_format(self):
        """Backup path must have timestamp."""
        path = create_backup_path("/etc/nginx/sites-enabled/example.com")
        
        assert path.startswith("/etc/nginx/backups/")
        assert "example.com.bak-" in path
        # Check timestamp format YYYYMMDD-HHMMSS
        import re
        assert re.search(r'\d{8}-\d{6}$', path)


class TestJobSystem:
    """Test job execution system."""
    
    def test_job_log_no_secrets(self):
        """Job logs must not contain secrets."""
        job = Job(id="test-123")
        
        # Simulate logging with potential secret
        message = "Connecting to server with password"
        job.log_info(message)
        
        # The message is allowed, but actual password values should never be logged
        assert "password" in job.logs[0].message.lower()
        # Verify no actual secret patterns
        assert "secret123" not in str(job.to_dict())
    
    def test_job_status_transitions(self):
        """Job status must transition correctly."""
        job = Job(id="test-456")
        
        assert job.status == JobStatus.QUEUED
        
        job.status = JobStatus.RUNNING
        assert job.status == JobStatus.RUNNING
        
        job.status = JobStatus.SUCCESS
        assert job.status == JobStatus.SUCCESS


class TestSafeApplyMock:
    """Test safe apply with mocked SSH."""
    
    def test_rollback_on_nginx_test_failure(self):
        """Must rollback on nginx -t failure."""
        from server_doctor.web.safe_apply import run_safe_apply
        from server_doctor.connector.ssh import CommandResult
        
        # Mock SSH connector
        mock_ssh = MagicMock()
        
        # Set up mock responses
        config_content = """server {
    server_name test.example.com;
    location / { }
}"""
        
        mock_ssh.read_file.return_value = config_content
        mock_ssh.file_exists.return_value = True
        
        def run_side_effect(cmd: str):
            if "mkdir -p /etc/nginx/backups" in cmd:
                return CommandResult(cmd, "", "", 0)
            if "cp '" in cmd:
                # Both backup and rollback copy commands.
                return CommandResult(cmd, "", "", 0)
            if "base64 -d" in cmd:
                return CommandResult(cmd, "", "", 0)
            if "mv '" in cmd:
                return CommandResult(cmd, "", "", 0)
            if "nginx -t" in cmd:
                return CommandResult(cmd, "", "nginx: configuration file test failed", 1)
            return CommandResult(cmd, "", "", 0)

        mock_ssh.run.side_effect = run_side_effect
        
        job = Job(id="rollback-test")
        snippet = "location /test { }"
        
        run_safe_apply(
            ssh=mock_ssh,
            job=job,
            nginx_file="/etc/nginx/sites-enabled/test.conf",
            domain="test.example.com",
            snippet=snippet,
        )
        
        # Job should be failed
        assert job.status == JobStatus.FAILED
        # Rollback should have been attempted
        assert job.result.get("rollback") is True
        # Should have logged rollback
        log_messages = [l.message for l in job.logs]
        assert any("rollback" in m.lower() for m in log_messages)
    
    def test_no_duplicate_insertion(self):
        """Must refuse to insert if marker exists."""
        from server_doctor.web.safe_apply import run_safe_apply
        
        mock_ssh = MagicMock()
        
        # Config already has the marker
        config_content = """server {
    server_name test.example.com;
    # --- server-doctor project: /existing (laravel) ---
    location /existing { }
    # --- end server-doctor project: /existing ---
}"""
        
        mock_ssh.read_file.return_value = config_content
        
        job = Job(id="duplicate-test")
        # Snippet with same path
        snippet = generate_laravel_location(
            path="/existing",
            root="/var/www/existing",
            fpm_socket="/run/php/php8.2-fpm.sock",
        )
        
        run_safe_apply(
            ssh=mock_ssh,
            job=job,
            nginx_file="/etc/nginx/sites-enabled/test.conf",
            domain="test.example.com",
            snippet=snippet,
        )
        
        # Should fail due to duplicate
        assert job.status == JobStatus.FAILED
        log_messages = [l.message for l in job.logs]
        assert any("already exists" in m.lower() for m in log_messages)
