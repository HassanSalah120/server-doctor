"""Apply Action - Apply configurations to server.

CONTRACT:
- read_only: False (MODIFIES SERVER)
- requires_backup: True
- rollback_support: True
- prerequisites: ["nginx -t passes"]

⚠️  WARNING: This action modifies the remote server!
"""

from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

from server_doctor.actions.report import ActionContract
from server_doctor.connector.ssh import SSHConnector


@dataclass
class ApplyResult:
    """Result of apply action."""

    success: bool
    backup_path: str | None = None
    error: str | None = None
    nginx_test_output: str = ""


class ApplyAction:
    """Apply configuration changes to a remote server.

    ⚠️  WARNING: This action MODIFIES the server!

    Safety measures:
    1. Always backs up existing config
    2. Tests with nginx -t before reload
    3. Only reloads if test passes
    4. Supports rollback
    """

    CONTRACT = ActionContract(
        read_only=False,
        requires_backup=True,
        rollback_support=True,
        prerequisites=["nginx -t passes"],
    )

    def __init__(self, ssh: SSHConnector) -> None:
        self.ssh = ssh

    def apply_config(
        self,
        config_content: str,
        target_path: str,
        *,
        backup: bool = True,
        test_only: bool = False,
    ) -> ApplyResult:
        """Apply a configuration file to the server.

        Args:
            config_content: The configuration content to write.
            target_path: Path on server (e.g., /etc/nginx/sites-available/mysite).
            backup: Whether to backup existing file first.
            test_only: If True, only test, don't actually write.

        Returns:
            ApplyResult with status and backup path.
        """
        result = ApplyResult(success=False)

        # Step 1: Backup existing file if it exists
        backup_path = None
        if backup and self.ssh.file_exists(target_path):
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            backup_path = f"{target_path}.backup_{timestamp}"

            backup_result = self.ssh.run(f"cp {target_path} {backup_path}")
            if not backup_result.success:
                result.error = f"Failed to backup: {backup_result.stderr}"
                return result

            result.backup_path = backup_path

        if test_only:
            result.success = True
            return result

        # Step 2: Write new configuration
        write_result = self.ssh.write_file(
            target_path,
            config_content,
            backup=False,  # We already backed up
        )
        if not write_result:
            result.error = "Failed to write configuration"
            return result

        # Step 3: Test nginx configuration
        test_result = self.ssh.run("nginx -t")
        result.nginx_test_output = test_result.stderr or test_result.stdout

        if not test_result.success:
            # Rollback!
            if backup_path:
                self.ssh.run(f"cp {backup_path} {target_path}")
            result.error = f"nginx -t failed: {result.nginx_test_output}"
            return result

        # Step 4: Reload nginx
        reload_result = self.ssh.run("systemctl reload nginx")
        if not reload_result.success:
            result.error = f"Failed to reload nginx: {reload_result.stderr}"
            return result

        result.success = True
        return result

    def rollback(self, target_path: str, backup_path: str) -> ApplyResult:
        """Rollback to a previous configuration.

        Args:
            target_path: Current config path.
            backup_path: Backup to restore from.

        Returns:
            ApplyResult with status.
        """
        result = ApplyResult(success=False)

        if not self.ssh.file_exists(backup_path):
            result.error = f"Backup not found: {backup_path}"
            return result

        # Restore backup
        restore_result = self.ssh.run(f"cp {backup_path} {target_path}")
        if not restore_result.success:
            result.error = f"Failed to restore: {restore_result.stderr}"
            return result

        # Test and reload
        test_result = self.ssh.run("nginx -t")
        if not test_result.success:
            result.error = f"nginx -t failed after rollback: {test_result.stderr}"
            return result

        reload_result = self.ssh.run("systemctl reload nginx")
        if not reload_result.success:
            result.error = f"Failed to reload after rollback: {reload_result.stderr}"
            return result

        result.success = True
        return result

    def enable_site(self, site_name: str) -> ApplyResult:
        """Enable a site by creating symlink in sites-enabled.

        Args:
            site_name: Name of the site in sites-available.

        Returns:
            ApplyResult with status.
        """
        result = ApplyResult(success=False)

        available = f"/etc/nginx/sites-available/{site_name}"
        enabled = f"/etc/nginx/sites-enabled/{site_name}"

        if not self.ssh.file_exists(available):
            result.error = f"Site not found: {available}"
            return result

        # Create symlink
        link_result = self.ssh.run(f"ln -sf {available} {enabled}")
        if not link_result.success:
            result.error = f"Failed to enable site: {link_result.stderr}"
            return result

        # Test and reload
        test_result = self.ssh.run("nginx -t")
        result.nginx_test_output = test_result.stderr or test_result.stdout

        if not test_result.success:
            # Remove the symlink
            self.ssh.run(f"rm {enabled}")
            result.error = f"nginx -t failed: {result.nginx_test_output}"
            return result

        reload_result = self.ssh.run("systemctl reload nginx")
        if not reload_result.success:
            result.error = f"Failed to reload: {reload_result.stderr}"
            return result

        result.success = True
        return result
