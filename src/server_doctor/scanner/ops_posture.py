"""Ops Posture Scanner - Extended host/container hardening signals."""

from __future__ import annotations

import json
import time

from server_doctor.connector.ssh import SSHConnector
from server_doctor.model.server import OpsPostureModel


class OpsPostureScanner:
    """Collect additional operational posture signals from a host."""

    def __init__(self, ssh: SSHConnector) -> None:
        self.ssh = ssh

    def scan(self) -> OpsPostureModel:
        posture = OpsPostureModel()
        self._collect_backup_signals(posture)
        self._collect_service_hardening(posture)
        self._collect_host_security_frameworks(posture)
        self._collect_ssh_hardening(posture)
        self._collect_docker_hardening(posture)
        return posture

    def _collect_backup_signals(self, posture: OpsPostureModel) -> None:
        tools_output = self._run_stdout(
            "for t in restic borg rsync rclone duplicity velero; "
            "do command -v \"$t\" >/dev/null 2>&1 && echo \"$t\"; done"
        )
        if tools_output:
            posture.backup_tools = sorted({line.strip() for line in tools_output.splitlines() if line.strip()})

        recent = self._run_stdout(
            "find /var/backups /backup /backups /srv/backups /opt/backups "
            "-maxdepth 3 -type f -printf '%T@ %p\\n' 2>/dev/null | sort -nr | head -n 20"
        )
        timestamps: list[float] = []
        recent_files: list[str] = []
        if recent:
            for raw in recent.splitlines():
                line = raw.strip()
                if not line:
                    continue
                parts = line.split(" ", 1)
                if len(parts) != 2:
                    continue
                try:
                    ts = float(parts[0])
                except ValueError:
                    continue
                path = parts[1].strip()
                if not path:
                    continue
                timestamps.append(ts)
                recent_files.append(path)

        if recent_files:
            posture.backup_recent_files = recent_files
            newest = max(timestamps)
            age_days = max(0.0, (time.time() - newest) / 86400.0)
            posture.backup_last_age_days = round(age_days, 2)
            return

        fallback = self._run_stdout(
            "find /var/backups /backup /backups /srv/backups /opt/backups "
            "-maxdepth 3 -type f -mtime -7 2>/dev/null | head -n 20"
        )
        if fallback:
            posture.backup_recent_files = [line.strip() for line in fallback.splitlines() if line.strip()]
            posture.backup_last_age_days = 7.0

    def _collect_service_hardening(self, posture: OpsPostureModel) -> None:
        posture.fail2ban_active = self._systemctl_is_active("fail2ban")
        posture.auditd_active = self._systemctl_is_active("auditd")

        if self.ssh.run("which apt 2>/dev/null", timeout=2).success:
            posture.unattended_upgrades_enabled = self._systemctl_is_enabled("unattended-upgrades")
            posture.unattended_upgrades_active = self._systemctl_is_active("unattended-upgrades")
        elif self.ssh.run("which dnf 2>/dev/null", timeout=2).success or self.ssh.run(
            "which yum 2>/dev/null", timeout=2
        ).success:
            posture.unattended_upgrades_enabled = self._systemctl_is_enabled("dnf-automatic.timer")
            posture.unattended_upgrades_active = self._systemctl_is_active("dnf-automatic.timer")

        ntp = self._run_stdout("timedatectl show -p NTPSynchronized --value 2>/dev/null")
        if ntp:
            value = ntp.strip().lower()
            if value in {"yes", "no"}:
                posture.ntp_synchronized = value == "yes"
                return

        status = self._run_stdout("timedatectl status 2>/dev/null")
        if not status:
            return
        for raw in status.splitlines():
            line = raw.strip().lower()
            if not line.startswith("system clock synchronized:"):
                continue
            posture.ntp_synchronized = "yes" in line
            return

    def _collect_host_security_frameworks(self, posture: OpsPostureModel) -> None:
        apparmor_state = self._run_stdout("cat /sys/module/apparmor/parameters/enabled 2>/dev/null")
        if apparmor_state:
            normalized = apparmor_state.strip().upper()
            if normalized.startswith("Y"):
                posture.apparmor_enabled = True
            elif normalized.startswith("N"):
                posture.apparmor_enabled = False
        elif self.ssh.run("which aa-status 2>/dev/null", timeout=2).success:
            val = self._run_stdout("aa-status --enabled >/dev/null 2>&1 && echo yes || echo no")
            if val:
                lowered = val.strip().lower()
                if lowered in {"yes", "no"}:
                    posture.apparmor_enabled = lowered == "yes"

        selinux = self._run_stdout("getenforce 2>/dev/null")
        if selinux:
            mode = selinux.strip().lower()
            if mode in {"enforcing", "permissive", "disabled"}:
                posture.selinux_mode = mode
                return

        enforce = self._run_stdout("cat /sys/fs/selinux/enforce 2>/dev/null")
        if enforce:
            v = enforce.strip()
            if v == "1":
                posture.selinux_mode = "enforcing"
            elif v == "0":
                posture.selinux_mode = "permissive"

    def _collect_ssh_hardening(self, posture: OpsPostureModel) -> None:
        if not self.ssh.run("which sshd 2>/dev/null", timeout=2).success:
            return

        out = self._run_stdout(
            "sshd -T 2>/dev/null | egrep "
            "'^(pubkeyauthentication|permitemptypasswords|maxauthtries|allowtcpforwarding) '"
        )
        if not out:
            return
        for raw in out.splitlines():
            parts = raw.strip().split()
            if len(parts) < 2:
                continue
            key, value = parts[0].lower(), parts[1].lower()
            if key == "pubkeyauthentication":
                posture.ssh_pubkey_authentication = value
            elif key == "permitemptypasswords":
                posture.ssh_permit_empty_passwords = value
            elif key == "maxauthtries":
                try:
                    posture.ssh_max_auth_tries = int(value)
                except ValueError:
                    pass
            elif key == "allowtcpforwarding":
                posture.ssh_allow_tcp_forwarding = value

    def _collect_docker_hardening(self, posture: OpsPostureModel) -> None:
        socket_mode = self._run_stdout("stat -c '%a' /var/run/docker.sock 2>/dev/null")
        if socket_mode and socket_mode.strip():
            posture.docker_socket_mode = socket_mode.strip()

        if not self.ssh.run("which docker 2>/dev/null", timeout=2).success:
            return

        id_output = self._run_stdout("docker ps -aq --no-trunc 2>/dev/null")
        if not id_output:
            return
        ids = [line.strip() for line in id_output.splitlines() if line.strip()]
        if not ids:
            return

        inspect = self.ssh.run(f"docker inspect {' '.join(ids)} 2>/dev/null", timeout=15)
        if not inspect.success or not inspect.stdout.strip():
            return
        try:
            details = json.loads(inspect.stdout)
        except json.JSONDecodeError:
            return
        if not isinstance(details, list):
            return

        for container in details:
            if not isinstance(container, dict):
                continue
            name = self._container_name(container)
            host_config = container.get("HostConfig") or {}
            config = container.get("Config") or {}
            if not isinstance(host_config, dict) or not isinstance(config, dict):
                continue

            if bool(host_config.get("Privileged")):
                posture.docker_privileged_containers.append(name)
            if str(host_config.get("NetworkMode", "")).lower() == "host":
                posture.docker_host_network_containers.append(name)
            if str(host_config.get("PidMode", "")).lower() == "host":
                posture.docker_host_pid_containers.append(name)
            if int(host_config.get("Memory") or 0) <= 0:
                posture.docker_no_memory_limit_containers.append(name)
            if not bool(host_config.get("ReadonlyRootfs")):
                posture.docker_no_readonly_rootfs_containers.append(name)

            user = str(config.get("User") or "").strip().lower()
            if user in {"", "0", "root"}:
                posture.docker_root_user_containers.append(name)

        posture.docker_privileged_containers = sorted(set(posture.docker_privileged_containers))
        posture.docker_host_network_containers = sorted(set(posture.docker_host_network_containers))
        posture.docker_host_pid_containers = sorted(set(posture.docker_host_pid_containers))
        posture.docker_no_memory_limit_containers = sorted(set(posture.docker_no_memory_limit_containers))
        posture.docker_no_readonly_rootfs_containers = sorted(set(posture.docker_no_readonly_rootfs_containers))
        posture.docker_root_user_containers = sorted(set(posture.docker_root_user_containers))

    def _run_stdout(self, cmd: str, timeout: float = 5) -> str | None:
        result = self.ssh.run(cmd, timeout=timeout)
        if not result.success:
            return None
        text = result.stdout.strip()
        return text if text else None

    def _systemctl_is_active(self, unit: str) -> bool | None:
        out = self._run_stdout(f"systemctl is-active {unit} 2>/dev/null || true")
        if not out:
            return None
        value = out.strip().lower()
        if value == "active":
            return True
        if value in {"inactive", "failed", "deactivating", "activating", "unknown", "not-found"}:
            return False
        return None

    def _systemctl_is_enabled(self, unit: str) -> bool | None:
        out = self._run_stdout(f"systemctl is-enabled {unit} 2>/dev/null || true")
        if not out:
            return None
        value = out.strip().lower()
        if value in {"enabled", "static", "indirect", "generated"}:
            return True
        if value in {"disabled", "masked", "not-found"}:
            return False
        return None

    def _container_name(self, container: dict) -> str:
        raw = str(container.get("Name") or "").strip()
        if raw:
            return raw.lstrip("/")
        cfg = container.get("Config") or {}
        fallback = str(cfg.get("Hostname") or "").strip()
        return fallback or "unknown"
