"""Tests for OpsPostureScanner."""

from __future__ import annotations

from unittest.mock import MagicMock

from server_doctor.scanner.ops_posture import OpsPostureScanner


def _res(success: bool, stdout: str = "") -> MagicMock:
    m = MagicMock()
    m.success = success
    m.stdout = stdout
    m.stderr = ""
    m.exit_code = 0 if success else 1
    return m


def test_ops_posture_scan_collects_backup_ssh_and_docker(mock_ssh_connector):
    scanner = OpsPostureScanner(mock_ssh_connector)

    inspect_json = """
[
  {
    "Name": "/api",
    "HostConfig": {
      "Privileged": true,
      "NetworkMode": "host",
      "PidMode": "host",
      "Memory": 0,
      "ReadonlyRootfs": false
    },
    "Config": {
      "User": ""
    }
  }
]
""".strip()

    def run_side_effect(cmd: str, **kwargs):
        if cmd.startswith("for t in restic"):
            return _res(True, "restic\nrsync\n")
        if "find /var/backups" in cmd and "-printf" in cmd:
            return _res(True, "1735689600.0 /var/backups/nightly.tar.gz\n")
        if "systemctl is-active fail2ban" in cmd:
            return _res(True, "active\n")
        if "systemctl is-active auditd" in cmd:
            return _res(True, "inactive\n")
        if "which apt" in cmd:
            return _res(True, "/usr/bin/apt\n")
        if "systemctl is-enabled unattended-upgrades" in cmd:
            return _res(True, "enabled\n")
        if "systemctl is-active unattended-upgrades" in cmd:
            return _res(True, "active\n")
        if "timedatectl show -p NTPSynchronized" in cmd:
            return _res(True, "yes\n")
        if "cat /sys/module/apparmor/parameters/enabled" in cmd:
            return _res(True, "Y\n")
        if "getenforce" in cmd:
            return _res(True, "Enforcing\n")
        if "which sshd" in cmd:
            return _res(True, "/usr/sbin/sshd\n")
        if "sshd -T" in cmd:
            return _res(
                True,
                (
                    "pubkeyauthentication yes\n"
                    "permitemptypasswords no\n"
                    "maxauthtries 4\n"
                    "allowtcpforwarding no\n"
                ),
            )
        if "stat -c '%a' /var/run/docker.sock" in cmd:
            return _res(True, "666\n")
        if "which docker" in cmd:
            return _res(True, "/usr/bin/docker\n")
        if "docker ps -aq --no-trunc" in cmd:
            return _res(True, "abc123\n")
        if cmd.startswith("docker inspect "):
            return _res(True, inspect_json)
        return _res(False, "")

    mock_ssh_connector.run.side_effect = run_side_effect
    posture = scanner.scan()

    assert posture.backup_tools == ["restic", "rsync"]
    assert posture.backup_recent_files == ["/var/backups/nightly.tar.gz"]
    assert posture.fail2ban_active is True
    assert posture.auditd_active is False
    assert posture.unattended_upgrades_enabled is True
    assert posture.unattended_upgrades_active is True
    assert posture.ntp_synchronized is True
    assert posture.apparmor_enabled is True
    assert posture.selinux_mode == "enforcing"

    assert posture.ssh_pubkey_authentication == "yes"
    assert posture.ssh_permit_empty_passwords == "no"
    assert posture.ssh_max_auth_tries == 4
    assert posture.ssh_allow_tcp_forwarding == "no"

    assert posture.docker_socket_mode == "666"
    assert posture.docker_privileged_containers == ["api"]
    assert posture.docker_host_network_containers == ["api"]
    assert posture.docker_host_pid_containers == ["api"]
    assert posture.docker_root_user_containers == ["api"]
    assert posture.docker_no_memory_limit_containers == ["api"]
    assert posture.docker_no_readonly_rootfs_containers == ["api"]
