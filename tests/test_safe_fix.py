"""Tests for SafeFixAction."""

from unittest.mock import MagicMock, patch

from rich.console import Console

from server_doctor.actions.safe_fix import FixResult, SafeFixAction
from server_doctor.connector.ssh import CommandResult
from server_doctor.model.evidence import Evidence, Severity
from server_doctor.model.finding import Finding


def _sample_wss_finding() -> Finding:
    return Finding(
        id="NGX-WSS-006",
        severity=Severity.INFO,
        confidence=0.8,
        condition="Missing forwarded headers for WebSocket",
        cause="Headers are not configured",
        evidence=[
            Evidence(
                source_file="/etc/nginx/sites-enabled/default",
                line_number=10,
                excerpt="location /ws",
                command="nginx -T",
            )
        ],
        treatment="Add forwarded headers",
        impact=["Backend may lose client context"],
    )


def test_dry_run_no_changes():
    """Dry-run mode should not write to remote files."""
    ssh = MagicMock()
    ssh.run.return_value = CommandResult(command="noop", stdout="", stderr="", exit_code=0)

    fixer = SafeFixAction(Console(quiet=True), ssh, dry_run=True)
    finding = _sample_wss_finding()

    with patch.object(
        SafeFixAction,
        "_fix_move_bak_files",
        return_value=FixResult("Cleanup .bak files", "dry-run", "noop", [], []),
    ) as mock_cleanup, patch.object(
        SafeFixAction,
        "_fix_proxy_headers",
        return_value=FixResult("Fix Proxy Headers", "dry-run", "noop", [], []),
    ) as mock_proxy:
        results = fixer.run([finding])

    assert len(results) == 2
    assert all(r.status == "dry-run" for r in results)
    mock_cleanup.assert_called_once()
    mock_proxy.assert_called_once()
    ssh.run.assert_not_called()


def test_backup_and_validation_failure():
    """Backup command should run and validation should fail on non-zero nginx -t."""
    ssh = MagicMock()
    ssh.run.side_effect = [
        CommandResult(command="cp file backup", stdout="", stderr="", exit_code=0),
        CommandResult(command="nginx -t", stdout="", stderr="test failed", exit_code=1),
    ]

    fixer = SafeFixAction(Console(quiet=True), ssh, dry_run=False)

    backup = fixer._backup_file("/etc/nginx/nginx.conf")
    assert backup.startswith("/etc/nginx/nginx.conf.")
    assert fixer._validate_nginx() is False
