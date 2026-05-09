"""Host Security Auditor - Analyzes SSH and OS security posture signals."""

from server_doctor.model.evidence import Evidence, Severity
from server_doctor.model.finding import Finding
from server_doctor.model.server import ServerModel


class HostSecurityAuditor:
    """Auditor for host-level security signals from baseline and ops data."""

    def __init__(self, model: ServerModel) -> None:
        self.model = model

    def audit(self) -> list[Finding]:
        findings: list[Finding] = []
        findings.extend(self._check_ssh_root_login())
        findings.extend(self._check_ssh_password_auth())
        findings.extend(self._check_ssh_empty_passwords())
        findings.extend(self._check_ssh_tcp_forwarding())
        findings.extend(self._check_fail2ban())
        findings.extend(self._check_unattended_upgrades())
        return findings

    def _check_ssh_root_login(self) -> list[Finding]:
        if not self.model.security_baseline:
            return []
        val = (self.model.security_baseline.ssh_permit_root_login or "").lower()
        if val not in {"yes", "without-password", "prohibit-password"}:
            return []

        if val == "yes":
            return [
                Finding(
                    id="HOST-001",
                    severity=Severity.WARNING,
                    confidence=0.95,
                    condition="SSH root login with password is permitted",
                    cause="PermitRootLogin is set to 'yes', allowing password-based root SSH login.",
                    evidence=[Evidence(
                        source_file="/etc/ssh/sshd_config",
                        line_number=1,
                        excerpt="PermitRootLogin yes",
                        command="sshd -T | grep permitrootlogin",
                    )],
                    treatment="Set PermitRootLogin prohibit-password and use key-based auth only.",
                    impact=[
                        "Root password brute-force becomes viable attack vector",
                        "Blast radius of credential compromise includes full host",
                    ],
                )
            ]
        return []

    def _check_ssh_password_auth(self) -> list[Finding]:
        val = None
        if self.model.security_baseline:
            val = (self.model.security_baseline.ssh_password_authentication or "").lower()
        if val not in {"yes", "on", "true"}:
            return []

        return [
            Finding(
                id="HOST-002",
                severity=Severity.WARNING,
                confidence=0.90,
                condition="SSH password authentication is enabled",
                cause="PasswordAuthentication allows password-based SSH login attempts.",
                evidence=[Evidence(
                    source_file="/etc/ssh/sshd_config",
                    line_number=1,
                    excerpt="PasswordAuthentication yes",
                    command="sshd -T | grep passwordauthentication",
                )],
                treatment="Enforce key-based authentication: set PasswordAuthentication no.",
                impact=[
                    "Higher brute-force and credential-stuffing risk",
                    "Password spraying attacks become viable",
                ],
            )
        ]

    def _check_ssh_empty_passwords(self) -> list[Finding]:
        if not self.model.ops_posture:
            return []
        val = (self.model.ops_posture.ssh_permit_empty_passwords or "").lower()
        if val not in {"yes", "on", "true"}:
            return []

        return [
            Finding(
                id="HOST-003",
                severity=Severity.CRITICAL,
                confidence=0.98,
                condition="SSH empty passwords are permitted",
                cause="PermitEmptyPasswords is enabled, allowing accounts with no password to log in.",
                evidence=[Evidence(
                    source_file="/etc/ssh/sshd_config",
                    line_number=1,
                    excerpt="PermitEmptyPasswords yes",
                    command="sshd -T | grep permitemptypasswords",
                )],
                treatment="Set PermitEmptyPasswords no and ensure all user accounts have strong passwords.",
                impact=[
                    "Any account with empty password can log in remotely",
                    "Immediate compromise risk",
                ],
            )
        ]

    def _check_ssh_tcp_forwarding(self) -> list[Finding]:
        if not self.model.ops_posture:
            return []
        val = (self.model.ops_posture.ssh_allow_tcp_forwarding or "").lower()
        if val not in {"yes", "on", "true", "all"}:
            return []

        return [
            Finding(
                id="HOST-004",
                severity=Severity.INFO,
                confidence=0.80,
                condition="SSH TCP forwarding is allowed",
                cause="AllowTcpForwarding is enabled, which can be used as a tunneling primitive.",
                evidence=[Evidence(
                    source_file="/etc/ssh/sshd_config",
                    line_number=1,
                    excerpt="AllowTcpForwarding yes",
                    command="sshd -T | grep allowtcpforwarding",
                )],
                treatment="Disable TCP forwarding if not needed: set AllowTcpForwarding no.",
                impact=[
                    "SSH tunnels could bypass firewall rules",
                    "Pivot risk if an SSH key is compromised",
                ],
            )
        ]

    def _check_fail2ban(self) -> list[Finding]:
        if not self.model.ops_posture:
            return []
        if self.model.ops_posture.fail2ban_active is None:
            return []
        if self.model.ops_posture.fail2ban_active:
            return []
        return [
            Finding(
                id="HOST-005",
                severity=Severity.INFO,
                confidence=0.80,
                condition="Fail2ban is not active",
                cause="fail2ban service is not running or not detected as active.",
                evidence=[Evidence(
                    source_file="ops_posture",
                    line_number=1,
                    excerpt="fail2ban_active=false",
                    command="systemctl status fail2ban",
                )],
                treatment="Install and enable fail2ban to protect against brute-force attacks.",
                impact=[
                    "No automated response to repeated failed login attempts",
                    "Higher brute-force persistence risk",
                ],
            )
        ]

    def _check_unattended_upgrades(self) -> list[Finding]:
        if not self.model.ops_posture:
            return []
        if self.model.ops_posture.unattended_upgrades_enabled is None:
            return []
        if self.model.ops_posture.unattended_upgrades_enabled:
            return []
        return [
            Finding(
                id="HOST-006",
                severity=Severity.INFO,
                confidence=0.80,
                condition="Unattended upgrades are not enabled",
                cause="Automatic security updates are not configured.",
                evidence=[Evidence(
                    source_file="ops_posture",
                    line_number=1,
                    excerpt="unattended_upgrades_enabled=false",
                    command="grep -r '\"Unattended-Upgrade::Enabled\"' /etc/apt/apt.conf.d/",
                )],
                treatment="Enable unattended-upgrades for automatic security patches.",
                impact=[
                    "Critical security updates may be delayed",
                    "Window of vulnerability exposure may be wider",
                ],
            )
        ]
