"""HTML Report Enhancements for DevOps Teams.

This module adds:
- Executive summary
- Compliance reporting
- Interactive filtering
- Remediation tracking
- Integration hooks
"""

from typing import Any
from server_doctor.model.finding import Finding, Severity
from server_doctor.model.server import ServerModel


class HTMLReportEnhancements:
    """Additional methods for enhanced HTML reporting."""

    @staticmethod
    def build_executive_summary(
        findings: list[Finding],
        report_score: int,
        model: ServerModel,
    ) -> dict[str, Any]:
        """Build executive summary for management overview."""
        critical_count = sum(1 for f in findings if f.severity == Severity.CRITICAL)
        warning_count = sum(1 for f in findings if f.severity == Severity.WARNING)
        info_count = sum(1 for f in findings if f.severity == Severity.INFO)
        
        # Calculate estimated fix time (rough heuristic)
        estimated_hours = (critical_count * 2) + (warning_count * 0.5) + (info_count * 0.1)
        
        # Count specific risks
        exposed_ports_count = sum(
            1 for f in findings 
            if "exposed" in f.condition.lower() or "public" in f.condition.lower()
        )
        
        ssl_expiry_count = sum(
            1 for f in findings
            if "ssl" in f.condition.lower() or "certificate" in f.condition.lower() or "tls" in f.condition.lower()
        )
        
        # Business impact assessment
        business_impacts = []
        if critical_count > 0:
            business_impacts.append(f"{critical_count} critical issues could cause service outages")
        if exposed_ports_count > 0:
            business_impacts.append(f"{exposed_ports_count} services exposed to internet without proper protection")
        if ssl_expiry_count > 0:
            business_impacts.append(f"{ssl_expiry_count} SSL/TLS certificates require attention")
        
        # Risk level
        if critical_count > 0:
            risk_level = "HIGH"
            risk_color = "critical"
        elif warning_count > 3:
            risk_level = "MEDIUM"
            risk_color = "warning"
        else:
            risk_level = "LOW"
            risk_color = "success"
        
        return {
            "critical_count": critical_count,
            "warning_count": warning_count,
            "info_count": info_count,
            "total_findings": len(findings),
            "estimated_fix_hours": round(estimated_hours, 1),
            "exposed_ports_count": exposed_ports_count,
            "ssl_expiry_count": ssl_expiry_count,
            "business_impacts": business_impacts,
            "risk_level": risk_level,
            "risk_color": risk_color,
            "health_score": report_score,
        }

    @staticmethod
    def build_compliance_status(findings: list[Finding], model: ServerModel) -> dict[str, Any]:
        """Build compliance status for various frameworks."""
        
        # PCI-DSS checks
        pci_checks = {
            "ssl_tls": not any("ssl" in f.condition.lower() or "tls" in f.condition.lower() for f in findings if f.severity == Severity.CRITICAL),
            "password_auth": not any("password" in f.condition.lower() and "ssh" in f.condition.lower() for f in findings),
            "firewall": not any("firewall" in f.condition.lower() for f in findings if f.severity == Severity.CRITICAL),
            "security_headers": not any("security header" in f.condition.lower() for f in findings),
            "dotfile_protection": not any("dotfile" in f.condition.lower() or ".env" in f.condition.lower() for f in findings),
        }
        pci_passing = sum(1 for v in pci_checks.values() if v)
        pci_total = len(pci_checks)
        pci_score = int((pci_passing / pci_total) * 100)
        
        # SOC2 checks
        soc2_checks = {
            "access_control": not any("exposed" in f.condition.lower() for f in findings if f.severity == Severity.CRITICAL),
            "encryption": not any("ssl" in f.condition.lower() or "tls" in f.condition.lower() for f in findings if f.severity == Severity.CRITICAL),
            "monitoring": True,  # Assume monitoring is in place if using this tool
            "backup": not any("backup" in f.condition.lower() for f in findings if f.severity == Severity.CRITICAL),
            "vulnerability_mgmt": not any("vuln" in f.id.lower() for f in findings if f.severity == Severity.CRITICAL),
        }
        soc2_passing = sum(1 for v in soc2_checks.values() if v)
        soc2_total = len(soc2_checks)
        soc2_score = int((soc2_passing / soc2_total) * 100)
        
        # CIS Benchmark checks
        cis_checks = {
            "nginx_version": model.nginx and model.nginx.version,
            "ssl_protocols": not any("ssl" in f.condition.lower() for f in findings if f.severity == Severity.CRITICAL),
            "file_permissions": not any("permission" in f.condition.lower() for f in findings),
            "default_configs": not any("default" in f.condition.lower() for f in findings),
            "security_headers": not any("security header" in f.condition.lower() for f in findings),
            "logging": True,  # Assume logging is configured
        }
        cis_passing = sum(1 for v in cis_checks.values() if v)
        cis_total = len(cis_checks)
        cis_score = int((cis_passing / cis_total) * 100)
        
        return {
            "pci_dss": {
                "score": pci_score,
                "passing": pci_passing,
                "total": pci_total,
                "checks": pci_checks,
            },
            "soc2": {
                "score": soc2_score,
                "passing": soc2_passing,
                "total": soc2_total,
                "checks": soc2_checks,
            },
            "cis_benchmark": {
                "score": cis_score,
                "passing": cis_passing,
                "total": cis_total,
                "checks": cis_checks,
            },
        }

    @staticmethod
    def build_remediation_tracker(findings: list[Finding]) -> list[dict[str, Any]]:
        """Build remediation tracking data for findings."""
        tracker = []
        for finding in findings:
            tracker.append({
                "id": finding.id,
                "condition": finding.condition,
                "severity": finding.severity.value.upper(),
                "status": "pending",  # Default status
                "assignee": "",
                "due_date": "",
                "notes": "",
                "estimated_hours": 2 if finding.severity == Severity.CRITICAL else 0.5,
            })
        return tracker

    @staticmethod
    def build_integration_config(model: ServerModel) -> dict[str, Any]:
        """Build integration configuration for external tools."""
        return {
            "jira": {
                "enabled": False,
                "project_key": "",
                "issue_type": "Bug",
                "priority_mapping": {
                    "CRITICAL": "Highest",
                    "WARNING": "High",
                    "INFO": "Medium",
                },
            },
            "slack": {
                "enabled": False,
                "webhook_url": "",
                "channel": "#devops-alerts",
                "mention_on_critical": True,
            },
            "pagerduty": {
                "enabled": False,
                "integration_key": "",
                "create_incident_on_critical": True,
            },
            "email": {
                "enabled": False,
                "recipients": [],
                "send_on_critical": True,
            },
        }

    @staticmethod
    def build_comparison_data(
        current_findings: list[Finding],
        baseline_findings: list[Finding] | None = None,
    ) -> dict[str, Any]:
        """Build comparison data between current and baseline scans."""
        if not baseline_findings:
            return {
                "has_baseline": False,
                "new_findings": [],
                "resolved_findings": [],
                "unchanged_findings": [],
            }
        
        current_ids = {f.id for f in current_findings}
        baseline_ids = {f.id for f in baseline_findings}
        
        new_findings = [f for f in current_findings if f.id not in baseline_ids]
        resolved_findings = [f for f in baseline_findings if f.id not in current_ids]
        unchanged_findings = [f for f in current_findings if f.id in baseline_ids]
        
        return {
            "has_baseline": True,
            "new_findings": new_findings,
            "resolved_findings": resolved_findings,
            "unchanged_findings": unchanged_findings,
            "new_count": len(new_findings),
            "resolved_count": len(resolved_findings),
            "unchanged_count": len(unchanged_findings),
        }

    @staticmethod
    def build_filter_categories(findings: list[Finding]) -> dict[str, list[str]]:
        """Build filter categories for interactive filtering."""
        categories = {
            "severity": ["all", "critical", "warning", "info"],
            "category": set(),
            "affected_service": set(),
        }
        
        for finding in findings:
            # Extract category from finding ID
            if "-" in finding.id:
                category = finding.id.split("-")[0]
                categories["category"].add(category)
            
            # Extract affected service from condition
            condition_lower = finding.condition.lower()
            if "nginx" in condition_lower:
                categories["affected_service"].add("nginx")
            if "php" in condition_lower:
                categories["affected_service"].add("php")
            if "docker" in condition_lower:
                categories["affected_service"].add("docker")
            if "ssl" in condition_lower or "tls" in condition_lower:
                categories["affected_service"].add("ssl/tls")
            if "mysql" in condition_lower:
                categories["affected_service"].add("mysql")
            if "redis" in condition_lower:
                categories["affected_service"].add("redis")
        
        return {
            "severity": categories["severity"],
            "category": sorted(list(categories["category"])),
            "affected_service": sorted(list(categories["affected_service"])),
        }
