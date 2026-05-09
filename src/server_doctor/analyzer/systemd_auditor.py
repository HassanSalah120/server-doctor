"""Systemd Auditor - Audits system services for stability and health.

Identifies services in crash loops and failed units.
"""

from server_doctor.model.evidence import Evidence, Severity
from server_doctor.model.finding import Finding
from server_doctor.model.server import ServerModel


class SystemdAuditor:
    """Auditor for Systemd services stability."""

    def __init__(self, model: ServerModel) -> None:
        self.model = model

    def audit(self) -> list[Finding]:
        """Run all Systemd diagnostic checks."""
        findings: list[Finding] = []
        
        if not hasattr(self.model, "runtime") or not self.model.runtime.systemd_services:
            return findings

        findings.extend(self._check_crash_loops())
        findings.extend(self._check_failed_units())
        
        return findings

    def _check_crash_loops(self) -> list[Finding]:
        """Check for services restarting frequently (SYSTEMD-1)."""
        findings: list[Finding] = []
        
        for svc in self.model.runtime.systemd_services:
            # Thresholds
            if svc.restart_count >= 5:
                severity = Severity.CRITICAL if svc.restart_count >= 20 else Severity.WARNING
                
                # If substate is auto-restart, it's definitely crashing
                is_active_crash = svc.substate == "auto-restart" or svc.state == "activating"
                
                findings.append(Finding(
                    id="SYSTEMD-1",
                    severity=severity,
                    confidence=1.0,
                    condition=f"Service '{svc.name}' is unstable (Restarts: {svc.restart_count})",
                    cause=f"Service has restarted {svc.restart_count} times recently. State: {svc.state}/{svc.substate}",
                    evidence=[Evidence(
                        source_file="systemd",
                        line_number=1,
                        excerpt=f"Unit: {svc.name}, Restarts: {svc.restart_count}, State: {svc.state}",
                        command=f"systemctl status {svc.name}"
                    )],
                    treatment=f"Check logs with 'journalctl -u {svc.name} -n 50' to identify crash reason.",
                    impact=["Service downtime", "Resource exhaustion", "Application instability"]
                ))
                
        return findings

    def _check_failed_units(self) -> list[Finding]:
        """Check for failed units (SYSTEMD-2)."""
        findings: list[Finding] = []
        
        for svc in self.model.runtime.systemd_services:
            if self._defer_failed_unit_to_specialized_auditor(svc.name):
                continue
            if svc.state == "failed" or svc.substate == "failed":
                findings.append(Finding(
                    id="SYSTEMD-2",
                    severity=Severity.CRITICAL,
                    confidence=1.0,
                    condition=f"Service '{svc.name}' has failed",
                    cause=f"Service is in failed state. Substate: {svc.substate}",
                    evidence=[Evidence(
                        source_file="systemd",
                        line_number=1,
                        excerpt=f"Unit: {svc.name}, State: failed",
                        command=f"systemctl status {svc.name}"
                    )],
                    treatment=f"Attempt restart 'systemctl restart {svc.name}' and check logs 'journalctl -u {svc.name}'.",
                    impact=["Service unavailable", "Dependent components failure"]
                ))
                
        return findings

    def _defer_failed_unit_to_specialized_auditor(self, service_name: str) -> bool:
        """Avoid duplicate/severity-conflicting findings for specialized domains."""
        return service_name == "certbot.service"
