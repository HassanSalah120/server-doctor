"""Ops Posture Auditor - Actionable findings from extended host/container posture."""

from __future__ import annotations

from server_doctor.model.evidence import Evidence, Severity
from server_doctor.model.finding import Finding
from server_doctor.model.server import NetworkEndpoint, ServerModel


class OpsPostureAuditor:
    """Auditor for advanced operational and hardening posture checks."""

    def __init__(self, model: ServerModel) -> None:
        self.model = model

    def audit(self) -> list[Finding]:
        if not hasattr(self.model, "ops_posture"):
            return []

        findings: list[Finding] = []
        findings.extend(self._check_backup_coverage())
        findings.extend(self._check_backup_recency())
        findings.extend(self._check_patch_automation())
        findings.extend(self._check_time_sync())
        findings.extend(self._check_fail2ban())
        findings.extend(self._check_mac_framework())
        findings.extend(self._check_ssh_extended())
        findings.extend(self._check_docker_socket_permissions())
        findings.extend(self._check_docker_runtime_hardening())
        return findings

    def _check_backup_coverage(self) -> list[Finding]:
        tools = self.model.ops_posture.backup_tools or []
        recent = self.model.ops_posture.backup_recent_files or []
        if tools or recent:
            return []

        return [
            Finding(
                id="OPS-BACKUP-1",
                severity=Severity.WARNING,
                confidence=0.78,
                condition="No backup tooling or recent backup artifacts detected",
                cause=(
                    "No common backup tools were detected and no recent files were found in "
                    "standard backup paths."
                ),
                evidence=[
                    Evidence(
                        source_file="backup-scan",
                        line_number=1,
                        excerpt="tools=none, recent_files=0",
                        command="find /var/backups /backup /backups /srv/backups /opt/backups",
                    )
                ],
                treatment=(
                    "Define and automate backups (for example restic/borg or scheduled snapshots) "
                    "and verify recoverability."
                ),
                impact=[
                    "Higher data-loss risk after host/application incidents",
                    "Longer recovery time objectives",
                ],
            )
        ]

    def _check_backup_recency(self) -> list[Finding]:
        age_days = self.model.ops_posture.backup_last_age_days
        if age_days is None or age_days <= 7:
            return []

        severity = Severity.CRITICAL if age_days > 30 else Severity.WARNING
        return [
            Finding(
                id="OPS-BACKUP-2",
                severity=severity,
                confidence=0.82,
                condition=f"Backup artifacts appear stale (last backup ~{age_days:.1f} days ago)",
                cause="Recent backups were not observed within a healthy operational window.",
                evidence=[
                    Evidence(
                        source_file="backup-scan",
                        line_number=1,
                        excerpt=f"backup_last_age_days={age_days:.2f}",
                        command="find ... -printf '%T@ %p'",
                    )
                ],
                treatment="Increase backup frequency and verify backup job execution/alerts.",
                impact=[
                    "Potentially large restore point gap",
                    "Higher business continuity risk",
                ],
            )
        ]

    def _check_patch_automation(self) -> list[Finding]:
        findings: list[Finding] = []
        enabled = self.model.ops_posture.unattended_upgrades_enabled
        active = self.model.ops_posture.unattended_upgrades_active
        pending_total = self.model.security_baseline.pending_updates_total or 0

        if enabled is False:
            severity = Severity.WARNING if pending_total >= 20 else Severity.INFO
            findings.append(
                Finding(
                    id="OPS-PATCH-1",
                    severity=severity,
                    confidence=0.80,
                    condition="Automatic package update service appears disabled",
                    cause=(
                        "Unattended update automation was not enabled, increasing dependence on manual patch cadence."
                    ),
                    evidence=[
                        Evidence(
                            source_file="systemd",
                            line_number=1,
                            excerpt=f"auto_updates_enabled={enabled}",
                            command="systemctl is-enabled unattended-upgrades|dnf-automatic.timer",
                        )
                    ],
                    treatment="Enable unattended update timers/services with maintenance guardrails.",
                    impact=[
                        "Security patch latency may increase",
                    ],
                )
            )

        if enabled is True and active is False:
            findings.append(
                Finding(
                    id="OPS-PATCH-2",
                    severity=Severity.INFO,
                    confidence=0.72,
                    condition="Automatic update service enabled but not currently active",
                    cause="The unit is enabled but not running at this check time.",
                    evidence=[
                        Evidence(
                            source_file="systemd",
                            line_number=1,
                            excerpt="enabled=true, active=false",
                            command="systemctl is-active unattended-upgrades|dnf-automatic.timer",
                        )
                    ],
                    treatment="Validate timer schedule/last-run status and alerting.",
                    impact=["Patch automation reliability may be inconsistent"],
                )
            )
        return findings

    def _check_time_sync(self) -> list[Finding]:
        if self.model.ops_posture.ntp_synchronized is not False:
            return []
        return [
            Finding(
                id="OPS-TIME-1",
                severity=Severity.WARNING,
                confidence=0.90,
                condition="Host clock is not synchronized via NTP",
                cause="System reports unsynchronized time.",
                evidence=[
                    Evidence(
                        source_file="timedatectl",
                        line_number=1,
                        excerpt="NTPSynchronized=no",
                        command="timedatectl show -p NTPSynchronized --value",
                    )
                ],
                treatment="Enable NTP synchronization (chrony/systemd-timesyncd) and verify sync state.",
                impact=[
                    "TLS validation, logs, and distributed auth flows can fail unpredictably",
                ],
            )
        ]

    def _check_fail2ban(self) -> list[Finding]:
        if self.model.ops_posture.fail2ban_active is not False:
            return []
        ssh_public = any(
            ep.port == 22 and ep.public_exposed for ep in self._network_endpoints()
        )
        severity = Severity.WARNING if ssh_public else Severity.INFO
        return [
            Finding(
                id="OPS-SSH-1",
                severity=severity,
                confidence=0.82,
                condition="Fail2ban is not active",
                cause="Brute-force protection service is inactive or not installed.",
                evidence=[
                    Evidence(
                        source_file="systemd",
                        line_number=1,
                        excerpt="fail2ban is-active => inactive",
                        command="systemctl is-active fail2ban",
                    )
                ],
                treatment="Install/enable fail2ban (or equivalent IDS/rate-limit controls) for SSH and auth endpoints.",
                impact=[
                    "Higher online brute-force exposure on internet-reachable services",
                ],
            )
        ]

    def _check_mac_framework(self) -> list[Finding]:
        apparmor = self.model.ops_posture.apparmor_enabled
        selinux = (self.model.ops_posture.selinux_mode or "").lower()

        if apparmor is True or selinux == "enforcing":
            return []
        if apparmor is None and not selinux:
            return []

        return [
            Finding(
                id="OPS-MAC-1",
                severity=Severity.WARNING,
                confidence=0.75,
                condition="No active mandatory access control framework detected",
                cause=(
                    f"AppArmor active={apparmor}; SELinux mode={self.model.ops_posture.selinux_mode or 'unknown'}."
                ),
                evidence=[
                    Evidence(
                        source_file="kernel-security",
                        line_number=1,
                        excerpt=f"apparmor={apparmor}, selinux={self.model.ops_posture.selinux_mode or 'unknown'}",
                        command="aa-status/getenforce",
                    )
                ],
                treatment="Enable and enforce AppArmor or SELinux profiles for key services.",
                impact=[
                    "Weaker process isolation and blast-radius containment",
                ],
            )
        ]

    def _check_ssh_extended(self) -> list[Finding]:
        findings: list[Finding] = []
        posture = self.model.ops_posture

        pubkey_auth = (posture.ssh_pubkey_authentication or "").lower()
        if pubkey_auth in {"no", "off", "false"}:
            findings.append(
                Finding(
                    id="OPS-SSH-2",
                    severity=Severity.WARNING,
                    confidence=0.90,
                    condition="SSH public key authentication is disabled",
                    cause="`PubkeyAuthentication` is set to a disabled state.",
                    evidence=[
                        Evidence(
                            source_file="/etc/ssh/sshd_config",
                            line_number=1,
                            excerpt=f"PubkeyAuthentication {pubkey_auth}",
                            command="sshd -T | grep pubkeyauthentication",
                        )
                    ],
                    treatment="Enable `PubkeyAuthentication yes` and enforce key-based auth.",
                    impact=[
                        "Password-only SSH posture is weaker against credential attacks",
                    ],
                )
            )

        empty_passwords = (posture.ssh_permit_empty_passwords or "").lower()
        if empty_passwords in {"yes", "on", "true"}:
            findings.append(
                Finding(
                    id="OPS-SSH-3",
                    severity=Severity.CRITICAL,
                    confidence=0.96,
                    condition="SSH permits empty passwords",
                    cause="`PermitEmptyPasswords yes` allows empty-password account logins.",
                    evidence=[
                        Evidence(
                            source_file="/etc/ssh/sshd_config",
                            line_number=1,
                            excerpt="PermitEmptyPasswords yes",
                            command="sshd -T | grep permitemptypasswords",
                        )
                    ],
                    treatment="Set `PermitEmptyPasswords no` and reload sshd immediately.",
                    impact=[
                        "Authentication bypass on misconfigured user accounts",
                    ],
                )
            )

        if posture.ssh_max_auth_tries is not None and posture.ssh_max_auth_tries > 6:
            findings.append(
                Finding(
                    id="OPS-SSH-4",
                    severity=Severity.WARNING,
                    confidence=0.84,
                    condition=f"SSH MaxAuthTries is high ({posture.ssh_max_auth_tries})",
                    cause="Higher retry limits increase brute-force attempt window per connection.",
                    evidence=[
                        Evidence(
                            source_file="/etc/ssh/sshd_config",
                            line_number=1,
                            excerpt=f"MaxAuthTries {posture.ssh_max_auth_tries}",
                            command="sshd -T | grep maxauthtries",
                        )
                    ],
                    treatment="Reduce `MaxAuthTries` to 3-6.",
                    impact=[
                        "Improves brute-force resistance when reduced",
                    ],
                )
            )

        tcp_forward = (posture.ssh_allow_tcp_forwarding or "").lower()
        if tcp_forward in {"yes", "all", "local", "remote"}:
            findings.append(
                Finding(
                    id="OPS-SSH-5",
                    severity=Severity.INFO,
                    confidence=0.70,
                    condition="SSH TCP forwarding is enabled",
                    cause="`AllowTcpForwarding` is enabled; this may be intentional for bastion workflows.",
                    evidence=[
                        Evidence(
                            source_file="/etc/ssh/sshd_config",
                            line_number=1,
                            excerpt=f"AllowTcpForwarding {tcp_forward}",
                            command="sshd -T | grep allowtcpforwarding",
                        )
                    ],
                    treatment="Disable (`AllowTcpForwarding no`) if port-forwarding is not required.",
                    impact=[
                        "Can be abused for lateral movement/tunneling after account compromise",
                    ],
                )
            )
        return findings

    def _check_docker_socket_permissions(self) -> list[Finding]:
        mode = (self.model.ops_posture.docker_socket_mode or "").strip()
        if not mode:
            return []
        try:
            perms = int(mode, 8)
        except ValueError:
            return []
        if perms & 0o002 == 0:
            return []
        return [
            Finding(
                id="OPS-DOCKER-1",
                severity=Severity.CRITICAL,
                confidence=0.95,
                condition="Docker socket is world-writable",
                cause=f"/var/run/docker.sock permissions are too permissive ({mode}).",
                evidence=[
                    Evidence(
                        source_file="/var/run/docker.sock",
                        line_number=1,
                        excerpt=f"mode={mode}",
                        command="stat -c '%a' /var/run/docker.sock",
                    )
                ],
                treatment="Restrict socket permissions/group membership (typically 660 root:docker).",
                impact=[
                    "Any local user can gain root-equivalent control via Docker API",
                ],
            )
        ]

    def _check_docker_runtime_hardening(self) -> list[Finding]:
        findings: list[Finding] = []
        posture = self.model.ops_posture
        public_containers = self._public_docker_container_names()

        risky_runtime_containers = set(posture.docker_privileged_containers)
        risky_runtime_containers.update(posture.docker_host_network_containers)
        risky_runtime_containers.update(posture.docker_host_pid_containers)

        if posture.docker_privileged_containers:
            findings.append(
                Finding(
                    id="OPS-DOCKER-2",
                    severity=Severity.CRITICAL,
                    confidence=0.92,
                    condition=f"{len(posture.docker_privileged_containers)} privileged Docker container(s) detected",
                    cause="Privileged containers run with broad host capabilities.",
                    evidence=[
                        self._docker_evidence(
                            "privileged: " + ", ".join(posture.docker_privileged_containers[:6])
                        )
                    ],
                    treatment="Remove `--privileged`; grant only explicit capabilities/devices needed.",
                    impact=[
                        "Container escape blast radius is significantly larger",
                    ],
                )
            )

        if posture.docker_host_network_containers:
            findings.append(
                Finding(
                    id="OPS-DOCKER-3",
                    severity=Severity.WARNING,
                    confidence=0.86,
                    condition=f"{len(posture.docker_host_network_containers)} container(s) use host network mode",
                    cause="Host networking bypasses container network isolation.",
                    evidence=[
                        self._docker_evidence(
                            "host-network: " + ", ".join(posture.docker_host_network_containers[:6])
                        )
                    ],
                    treatment="Prefer bridge/user-defined networks unless host networking is strictly required.",
                    impact=["Network segmentation and policy controls are reduced"],
                )
            )

        if posture.docker_host_pid_containers:
            findings.append(
                Finding(
                    id="OPS-DOCKER-4",
                    severity=Severity.WARNING,
                    confidence=0.86,
                    condition=f"{len(posture.docker_host_pid_containers)} container(s) share host PID namespace",
                    cause="Host PID mode exposes host process visibility to containers.",
                    evidence=[
                        self._docker_evidence("host-pid: " + ", ".join(posture.docker_host_pid_containers[:6]))
                    ],
                    treatment="Avoid `--pid=host` unless required for specialized observability workloads.",
                    impact=["Process isolation is weakened"],
                )
            )

        if posture.docker_root_user_containers:
            root_scope = sorted(
                set(posture.docker_root_user_containers)
                & (public_containers | risky_runtime_containers)
            )
        else:
            root_scope = []

        if root_scope:
            findings.append(
                Finding(
                    id="OPS-DOCKER-5",
                    severity=Severity.INFO,
                    confidence=0.74,
                    condition=f"{len(root_scope)} container(s) run as root user",
                    cause=(
                        "Containers default to root when no explicit `USER` is configured. "
                        "This finding is limited to public-facing or otherwise high-risk runtime scopes."
                    ),
                    evidence=[
                        self._docker_evidence("root-user: " + ", ".join(root_scope[:6]))
                    ],
                    treatment="Use non-root container users where feasible.",
                    impact=["Privilege escalation impact increases if container is compromised"],
                )
            )

        if posture.docker_no_memory_limit_containers:
            severity = Severity.WARNING if len(posture.docker_no_memory_limit_containers) >= 2 else Severity.INFO
            findings.append(
                Finding(
                    id="OPS-DOCKER-6",
                    severity=severity,
                    confidence=0.80,
                    condition=f"{len(posture.docker_no_memory_limit_containers)} container(s) have no memory limit",
                    cause="Unset memory limits can cause noisy-neighbor and OOM instability.",
                    evidence=[
                        self._docker_evidence(
                            "no-memory-limit: " + ", ".join(posture.docker_no_memory_limit_containers[:6])
                        )
                    ],
                    treatment="Set `mem_limit`/`--memory` based on service SLOs and host capacity.",
                    impact=["Single-container spikes can degrade host/service availability"],
                )
            )

        if posture.docker_no_readonly_rootfs_containers:
            writable_scope = sorted(
                set(posture.docker_no_readonly_rootfs_containers)
                & (public_containers | risky_runtime_containers)
            )
        else:
            writable_scope = []

        if writable_scope:
            findings.append(
                Finding(
                    id="OPS-DOCKER-7",
                    severity=Severity.INFO,
                    confidence=0.70,
                    condition=f"{len(writable_scope)} container(s) allow writable root filesystem",
                    cause=(
                        "Writable root filesystems increase persistence options post-compromise. "
                        "This finding is limited to public-facing or otherwise high-risk runtime scopes."
                    ),
                    evidence=[
                        self._docker_evidence(
                            "writable-rootfs: " + ", ".join(writable_scope[:6])
                        )
                    ],
                    treatment="Use read-only rootfs plus explicit writable mounts for required paths.",
                    impact=["Hardens runtime immutability and reduces persistence techniques"],
                )
            )
        return findings

    def _public_docker_container_names(self) -> set[str]:
        containers = getattr(self.model.services, "docker_containers", []) or []
        public: set[str] = set()

        for container in containers:
            name = (container.name or "").strip()
            if not name:
                continue
            for port in container.ports or []:
                if port.host_port is None:
                    continue
                if self._is_public_bind_ip(port.host_ip):
                    public.add(name)
                    break

        return public

    @staticmethod
    def _is_public_bind_ip(host_ip: str | None) -> bool:
        ip = (host_ip or "").strip().lower()
        if not ip:
            return True
        if ip in {"0.0.0.0", "::", "[::]", "*"}:
            return True
        if ip.startswith("127.") or ip == "::1":
            return False
        return True

    def _network_endpoints(self) -> list[NetworkEndpoint]:
        if not hasattr(self.model, "network_surface"):
            return []
        return list(self.model.network_surface.endpoints or [])

    def _docker_evidence(self, excerpt: str) -> Evidence:
        return Evidence(
            source_file="docker",
            line_number=1,
            excerpt=excerpt,
            command="docker inspect $(docker ps -aq)",
        )
