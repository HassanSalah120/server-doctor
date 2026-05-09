"""Tests for dependency posture devops check."""

import server_doctor.checks.devops.dependency_posture_auditor  # noqa: F401
from server_doctor.checks import CheckContext
from server_doctor.checks.devops.dependency_posture_auditor import DependencyPostureAuditor
from server_doctor.model.evidence import Severity
from server_doctor.model.server import DependencyManagerStatus, ServerModel, SupplyChainModel, SupplyChainRepoModel


def test_dependency_posture_auditor_reports_outdated_backlog():
    model = ServerModel(hostname="test")
    model.supply_chain = SupplyChainModel(
        enabled=True,
        repo_paths=["/repo"],
        repos=[
            SupplyChainRepoModel(
                path="/repo",
                dependency_managers=[
                    DependencyManagerStatus(
                        manager="npm",
                        ecosystem="Node.js / JavaScript",
                        status="checked",
                        outdated_count=12,
                        sample=["express", "dotenv"],
                        check_command="npm outdated --json",
                    ),
                    DependencyManagerStatus(
                        manager="composer",
                        ecosystem="PHP",
                        status="checked",
                        outdated_count=11,
                        sample=["laravel/framework"],
                        check_command="composer outdated --format=json --direct",
                    ),
                ],
            )
        ],
    )

    findings = DependencyPostureAuditor().run(CheckContext(model=model))
    dep = next(f for f in findings if f.id == "SC-DEP-001")
    assert dep.severity == Severity.WARNING
    assert "23 package(s)" in dep.condition


def test_dependency_posture_auditor_reports_skipped_checks():
    model = ServerModel(hostname="test")
    model.supply_chain = SupplyChainModel(
        enabled=True,
        repo_paths=["/repo"],
        repos=[
            SupplyChainRepoModel(
                path="/repo",
                dependency_managers=[
                    DependencyManagerStatus(
                        manager="nuget",
                        ecosystem=".NET",
                        status="unavailable",
                        error="Command not found: dotnet",
                    ),
                    DependencyManagerStatus(
                        manager="ant",
                        ecosystem="Java",
                        status="unsupported",
                        error="No standardized outdated command for this manager",
                    ),
                ],
            )
        ],
    )

    findings = DependencyPostureAuditor().run(CheckContext(model=model))
    skipped = next(f for f in findings if f.id == "SC-DEP-002")
    assert skipped.severity == Severity.INFO
    assert "2 manager(s)" in skipped.condition


def test_dependency_posture_auditor_reports_vulnerabilities():
    model = ServerModel(hostname="test")
    model.supply_chain = SupplyChainModel(
        enabled=True,
        repo_paths=["/repo"],
        repos=[
            SupplyChainRepoModel(
                path="/repo",
                dependency_managers=[
                    DependencyManagerStatus(
                        manager="npm",
                        ecosystem="Node.js / JavaScript",
                        status="checked",
                        outdated_count=3,
                        vulnerability_count=10,
                        vulnerability_summary="high=5, moderate=3, low=2",
                        vulnerability_sample=["lodash", "express"],
                        audit_command="npm audit --omit=dev --json",
                    )
                ],
            )
        ],
    )

    findings = DependencyPostureAuditor().run(CheckContext(model=model))
    vuln = next(f for f in findings if f.id == "SC-DEP-003")
    assert vuln.severity == Severity.WARNING
    assert "10 issue(s)" in vuln.condition
