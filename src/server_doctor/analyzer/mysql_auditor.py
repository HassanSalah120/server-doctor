"""MySQL Auditor - Audits MySQL exposure and operability signals."""

from server_doctor.model.evidence import Evidence, Severity
from server_doctor.model.finding import Finding
from server_doctor.model.server import ServiceState, ServerModel


class MySQLAuditor:
    """Auditor for MySQL/MariaDB runtime posture."""

    def __init__(self, model: ServerModel) -> None:
        self.model = model

    def audit(self) -> list[Finding]:
        """Run MySQL checks."""
        findings: list[Finding] = []

        if not hasattr(self.model, "services") or self.model.services.mysql.capability.value == "none":
            return findings

        findings.extend(self._check_public_exposure())
        findings.extend(self._check_stopped_with_config())
        return findings

    def _check_public_exposure(self) -> list[Finding]:
        findings: list[Finding] = []
        mysql_state = self.model.services.mysql.state
        if mysql_state != ServiceState.RUNNING:
            return findings

        bind_addresses = self.model.services.mysql_bind_addresses
        public_addrs = [a for a in bind_addresses if a in ("0.0.0.0", "::", "*")]
        if not public_addrs:
            return findings

        firewall_state = self.model.services.firewall
        severity = Severity.WARNING if firewall_state == "present" else Severity.CRITICAL
        ports = self.model.services.mysql.listening_ports or [3306]

        findings.append(
            Finding(
                id="MYSQL-1",
                severity=severity,
                confidence=0.95,
                condition="MySQL is bound to a public interface",
                cause=(
                    f"MySQL listens on {', '.join(sorted(set(public_addrs)))} "
                    f"for port(s) {', '.join(str(p) for p in ports)}."
                ),
                evidence=[
                    Evidence(
                        source_file="mysql-runtime",
                        line_number=1,
                        excerpt=f"bind={addr} ports={ports}",
                        command="ss -lntp | grep mysqld",
                    )
                    for addr in sorted(set(public_addrs))
                ],
                treatment=(
                    "Bind MySQL to localhost/private network only:\n"
                    "    bind-address = 127.0.0.1\n"
                    "and restrict exposure with host firewall/security groups."
                ),
                impact=[
                    "Remote brute-force and exploitation surface increases",
                    "Data exfiltration risk if authentication or network ACLs are weak",
                ],
            )
        )
        return findings

    def _check_stopped_with_config(self) -> list[Finding]:
        findings: list[Finding] = []
        if (
            self.model.services.mysql.state == ServiceState.STOPPED
            and self.model.services.mysql_config_detected
        ):
            findings.append(
                Finding(
                    id="MYSQL-2",
                    severity=Severity.INFO,
                    confidence=0.75,
                    condition="MySQL configuration detected but service is stopped",
                    cause="MySQL appears installed/configured, but no active mysqld process was detected.",
                    evidence=[
                        Evidence(
                            source_file="/etc/mysql",
                            line_number=1,
                            excerpt="Config files detected; runtime not active",
                            command="ps aux | grep [m]ysqld",
                        )
                    ],
                    treatment=(
                        "If MySQL is required, start and validate the service:\n"
                        "    systemctl status mysql\n"
                        "    systemctl start mysql"
                    ),
                    impact=[
                        "Database-dependent applications may fail to serve requests",
                    ],
                )
            )
        return findings
