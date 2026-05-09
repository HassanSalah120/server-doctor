from __future__ import annotations

from dataclasses import dataclass

from server_doctor.checks import BaseCheck, CheckContext, register_check
from server_doctor.model.evidence import Evidence, Severity
from server_doctor.model.finding import Finding


@dataclass
@register_check
class DependencyPostureAuditor(BaseCheck):
    @property
    def category(self) -> str:
        return "devops"

    @property
    def requires_ssh(self) -> bool:
        return False

    def run(self, context: CheckContext) -> list[Finding]:
        sc = getattr(context.model, "supply_chain", None)
        if not sc or not getattr(sc, "enabled", False):
            return []

        findings: list[Finding] = []
        for repo in getattr(sc, "repos", []) or []:
            manager_rows = list(getattr(repo, "dependency_managers", []) or [])
            if not manager_rows:
                continue

            outdated = [
                row for row in manager_rows
                if row.status == "checked" and (row.outdated_count or 0) > 0
            ]
            vulnerable = [
                row for row in manager_rows
                if row.status == "checked" and (row.vulnerability_count or 0) > 0
            ]
            skipped = [
                row for row in manager_rows
                if row.status in {"unavailable", "unsupported", "error"}
            ]

            if outdated:
                total_updates = sum(row.outdated_count or 0 for row in outdated)
                severity = Severity.WARNING if total_updates >= 20 else Severity.INFO
                summary = ", ".join(
                    f"{row.manager}={row.outdated_count}" for row in outdated[:8]
                )
                evidence = [
                    Evidence(
                        source_file=repo.path,
                        line_number=1,
                        excerpt=(
                            f"{row.manager} ({row.ecosystem}) outdated={row.outdated_count}; "
                            f"sample={', '.join(row.sample[:3]) if row.sample else 'n/a'}"
                        ),
                        command=row.check_command or "dependency manager check",
                    )
                    for row in outdated[:10]
                ]
                findings.append(
                    Finding(
                        id="SC-DEP-001",
                        severity=severity,
                        confidence=0.75,
                        condition=(
                            f"Dependency updates pending in {repo.path} "
                            f"({total_updates} package(s) across {len(outdated)} manager(s))"
                        ),
                        cause=(
                            "Dependency manager outdated checks reported available upgrades "
                            f"for: {summary}."
                        ),
                        evidence=evidence,
                        treatment=(
                            "Review and upgrade dependencies manager-by-manager in a controlled window.\n"
                            "Examples: npm outdated, yarn outdated, pnpm outdated, composer outdated,\n"
                            "pip list --outdated, poetry show --outdated, dotnet list package --outdated."
                        ),
                        impact=[
                            "Increased exposure to known dependency vulnerabilities",
                            "Harder future upgrades due to version drift",
                        ],
                    )
                )

            if vulnerable:
                total_vulns = sum(row.vulnerability_count or 0 for row in vulnerable)
                has_critical = any(
                    "critical=" in (row.vulnerability_summary or "").lower()
                    for row in vulnerable
                )
                severity = Severity.WARNING if total_vulns < 20 and not has_critical else Severity.CRITICAL
                evidence = [
                    Evidence(
                        source_file=repo.path,
                        line_number=1,
                        excerpt=(
                            f"{row.manager} vulnerabilities={row.vulnerability_count}; "
                            f"summary={row.vulnerability_summary or 'n/a'}; "
                            f"sample={', '.join(row.vulnerability_sample[:3]) if row.vulnerability_sample else 'n/a'}"
                        ),
                        command=row.audit_command or row.check_command or "dependency audit",
                    )
                    for row in vulnerable[:10]
                ]
                findings.append(
                    Finding(
                        id="SC-DEP-003",
                        severity=severity,
                        confidence=0.8,
                        condition=(
                            f"Dependency vulnerabilities detected in {repo.path} "
                            f"({total_vulns} issue(s) across {len(vulnerable)} manager(s))"
                        ),
                        cause=(
                            "Dependency security audit commands reported vulnerabilities "
                            "in project-level package managers."
                        ),
                        evidence=evidence,
                        treatment=(
                            "Triage and patch vulnerable dependencies using manager-specific workflows.\n"
                            "Examples: npm audit fix, yarn npm audit, pnpm audit, composer audit,\n"
                            "and equivalent ecosystem security tooling."
                        ),
                        impact=[
                            "Known vulnerable libraries may be reachable in production paths",
                            "Higher exploitability and incident response risk",
                        ],
                    )
                )

            if skipped:
                evidence = [
                    Evidence(
                        source_file=repo.path,
                        line_number=1,
                        excerpt=f"{row.manager} status={row.status}: {row.error or 'check not available'}",
                        command=row.check_command or "n/a",
                    )
                    for row in skipped[:10]
                ]
                findings.append(
                    Finding(
                        id="SC-DEP-002",
                        severity=Severity.INFO,
                        confidence=0.65,
                        condition=(
                            f"Dependency manager upgrade checks were skipped/failed in {repo.path} "
                            f"({len(skipped)} manager(s))"
                        ),
                        cause=(
                            "One or more detected dependency managers could not be checked "
                            "because tooling is unavailable, unsupported, or command execution failed."
                        ),
                        evidence=evidence,
                        treatment=(
                            "Install missing package-manager tooling (when relevant) or run upgrade checks "
                            "inside the CI/build environment where these tools are available."
                        ),
                        impact=[
                            "Dependency risk posture may be incomplete for this repository",
                        ],
                    )
                )

        return findings
