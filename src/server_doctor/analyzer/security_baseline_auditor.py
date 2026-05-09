"""Security Baseline Auditor - SSH hardening and patch posture checks."""

from server_doctor.model.evidence import Evidence, Severity
from server_doctor.model.finding import Finding
from server_doctor.model.server import ServerModel


class SecurityBaselineAuditor:
    """Auditor for SSH and patch baseline signals."""

    def __init__(self, model: ServerModel) -> None:
        self.model = model

    def audit(self) -> list[Finding]:
        findings: list[Finding] = []
        if not hasattr(self.model, "security_baseline"):
            return findings

        findings.extend(self._check_ssh_root_login())
        findings.extend(self._check_ssh_password_auth())
        findings.extend(self._check_pending_security_updates())
        findings.extend(self._check_reboot_required())
        return findings

    def _check_ssh_root_login(self) -> list[Finding]:
        value = (self.model.security_baseline.ssh_permit_root_login or "").lower()
        if value != "yes":
            return []

        return [
            Finding(
                id="SSH-1",
                severity=Severity.WARNING,
                confidence=0.95,
                condition="SSH root login is enabled",
                cause="`PermitRootLogin yes` allows direct root SSH authentication.",
                evidence=[
                    Evidence(
                        source_file="/etc/ssh/sshd_config",
                        line_number=1,
                        excerpt="PermitRootLogin yes",
                        command="sshd -T | grep permitrootlogin",
                    )
                ],
                treatment="Set `PermitRootLogin no` (or `prohibit-password` at minimum) and reload sshd.",
                impact=[
                    "Increases blast radius of credential compromise",
                    "Raises brute-force and privileged access risk",
                ],
            )
        ]

    def _check_ssh_password_auth(self) -> list[Finding]:
        value = (self.model.security_baseline.ssh_password_authentication or "").lower()
        if value not in {"yes", "on", "true"}:
            return []

        return [
            Finding(
                id="SSH-2",
                severity=Severity.WARNING,
                confidence=0.90,
                condition="SSH password authentication is enabled",
                cause="`PasswordAuthentication yes` allows password-based SSH login.",
                evidence=[
                    Evidence(
                        source_file="/etc/ssh/sshd_config",
                        line_number=1,
                        excerpt="PasswordAuthentication yes",
                        command="sshd -T | grep passwordauthentication",
                    )
                ],
                treatment="Prefer key-based auth: set `PasswordAuthentication no` and enforce SSH keys.",
                impact=[
                    "Higher brute-force risk compared to key-only SSH",
                    "Credential stuffing attacks become more viable",
                ],
            )
        ]

    def _check_pending_security_updates(self) -> list[Finding]:
        pending_security = self.model.security_baseline.pending_security_updates
        pending_total = self.model.security_baseline.pending_updates_total
        package_manager = self._package_manager()
        manager_token = self._package_manager_token(package_manager)
        manager_desc = self._package_manager_description(package_manager)
        security_command = self._security_update_command(package_manager)
        updates_command = self._pending_update_command(package_manager)
        findings: list[Finding] = []

        if pending_security is not None and pending_security > 0:
            severity = Severity.CRITICAL if pending_security >= 20 else Severity.WARNING
            findings.append(
                Finding(
                    id="PATCH-1",
                    severity=severity,
                    confidence=0.85,
                    condition=f"{pending_security} pending {manager_token} security update(s) detected",
                    cause=(
                        f"{manager_desc} metadata indicates unpatched host OS security updates. "
                        "This signal is separate from npm/composer/pip dependency posture."
                    ),
                    evidence=[
                        Evidence(
                            source_file="package-manager",
                            line_number=1,
                            excerpt=f"security_updates={pending_security}, total_updates={pending_total}",
                            command=security_command,
                        )
                    ],
                    treatment="Apply security updates in a maintenance window and restart affected services.",
                    impact=[
                        "Known vulnerabilities may remain exploitable",
                        "Higher incident and compliance risk",
                    ],
                )
            )
        elif pending_total is not None and pending_total > 50:
            findings.append(
                Finding(
                    id="PATCH-2",
                    severity=Severity.INFO,
                    confidence=0.70,
                    condition=f"{pending_total} {manager_token} package update(s) pending",
                    cause=(
                        f"Large backlog of pending host OS package updates detected via {manager_desc}. "
                        "This finding does not represent application dependency manager updates."
                    ),
                    evidence=[
                        Evidence(
                            source_file="package-manager",
                            line_number=1,
                            excerpt=f"total_updates={pending_total}",
                            command=updates_command,
                        )
                    ],
                    treatment="Review update cadence and apply outstanding updates regularly.",
                    impact=[
                        "Operational drift from patched baseline",
                    ],
                )
            )

        return findings

    def _package_manager(self) -> str:
        value = (self.model.security_baseline.package_manager or "").strip().lower()
        return value if value in {"apt", "dnf", "yum"} else "os-package-manager"

    @staticmethod
    def _package_manager_token(value: str) -> str:
        if value in {"apt", "dnf", "yum"}:
            return value.upper()
        return "OS package-manager"

    @staticmethod
    def _package_manager_description(value: str) -> str:
        if value == "apt":
            return "APT (Ubuntu/Debian)"
        if value == "dnf":
            return "DNF (Fedora/RHEL)"
        if value == "yum":
            return "YUM (RHEL/CentOS)"
        return "host OS package manager"

    @staticmethod
    def _security_update_command(value: str) -> str:
        if value == "apt":
            return "apt list --upgradable | grep -i security"
        if value == "dnf":
            return "dnf -q updateinfo list security"
        if value == "yum":
            return "yum -q updateinfo list security all"
        return "system package manager security listing"

    @staticmethod
    def _pending_update_command(value: str) -> str:
        if value == "apt":
            return "apt list --upgradable"
        if value == "dnf":
            return "dnf -q check-update"
        if value == "yum":
            return "yum -q check-update"
        return "system package manager update listing"

    def _check_reboot_required(self) -> list[Finding]:
        if not self.model.security_baseline.reboot_required:
            return []

        severity = Severity.WARNING if (self.model.security_baseline.pending_security_updates or 0) > 0 else Severity.INFO
        return [
            Finding(
                id="PATCH-3",
                severity=severity,
                confidence=0.90,
                condition="System reboot required after updates",
                cause="Host indicates that a reboot is required to complete update activation.",
                evidence=[
                    Evidence(
                        source_file="/var/run/reboot-required",
                        line_number=1,
                        excerpt="reboot-required present",
                        command="test -f /var/run/reboot-required",
                    )
                ],
                treatment="Schedule and perform a controlled reboot to activate patched kernel/libraries.",
                impact=[
                    "Security fixes may not be fully active until reboot",
                ],
            )
        ]
