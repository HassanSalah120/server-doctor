"""Tests for SecurityBaselineScanner."""

from unittest.mock import MagicMock

from server_doctor.scanner.security_baseline import SecurityBaselineScanner


def test_scan_ssh_effective_config(mock_ssh_connector):
    scanner = SecurityBaselineScanner(mock_ssh_connector)

    def run_side_effect(cmd, **kwargs):
        if "which sshd" in cmd:
            return MagicMock(success=True, stdout="/usr/sbin/sshd\n")
        if "sshd -T" in cmd:
            return MagicMock(success=True, stdout="permitrootlogin yes\npasswordauthentication no\n")
        if "which apt" in cmd:
            return MagicMock(success=False, stdout="")
        if "which dnf" in cmd:
            return MagicMock(success=False, stdout="")
        if "which yum" in cmd:
            return MagicMock(success=False, stdout="")
        if "reboot-required" in cmd:
            return MagicMock(success=True, stdout="no\n")
        return MagicMock(success=False, stdout="")

    mock_ssh_connector.run.side_effect = run_side_effect

    baseline = scanner.scan()
    assert baseline.ssh_permit_root_login == "yes"
    assert baseline.ssh_password_authentication == "no"
    assert baseline.reboot_required is False


def test_scan_apt_updates_and_reboot(mock_ssh_connector):
    scanner = SecurityBaselineScanner(mock_ssh_connector)

    apt_output = """Listing...
openssl/ubuntu-security 1.1.1f-1ubuntu2.22 amd64 [upgradable from: 1.1.1f-1ubuntu2.21]
curl/ubuntu-updates 7.68.0-1ubuntu2.24 amd64 [upgradable from: 7.68.0-1ubuntu2.23]
"""

    def run_side_effect(cmd, **kwargs):
        if "which sshd" in cmd:
            return MagicMock(success=False, stdout="")
        if "which apt" in cmd:
            return MagicMock(success=True, stdout="/usr/bin/apt\n")
        if "apt list --upgradable" in cmd:
            return MagicMock(success=True, stdout=apt_output)
        if "reboot-required" in cmd:
            return MagicMock(success=True, stdout="yes\n")
        return MagicMock(success=False, stdout="")

    mock_ssh_connector.run.side_effect = run_side_effect
    mock_ssh_connector.read_file.return_value = ""

    baseline = scanner.scan()
    assert baseline.package_manager == "apt"
    assert baseline.pending_updates_total == 2
    assert baseline.pending_security_updates == 1
    assert baseline.reboot_required is True
