
import pytest
from server_doctor.ai.diagnoser import generate_diagnosis, DiagnosisContext, RuleBasedProvider
from server_doctor.model.finding import Finding
from server_doctor.model.evidence import Evidence, Severity

def test_rule_based_provider():
    provider = RuleBasedProvider()
    
    # Mock evidence needed for Finding
    evidence = Evidence(
        source_file="nginx.conf",
        line_number=10,
        excerpt="server { ... }",
        command=""
    )
    
    # Mock finding
    finding = Finding(
        id="SEC-HEAD-1",
        severity=Severity.WARNING,
        # category="security", # Finding doesn't have category attribute
        condition="Missing Security Headers",
        cause="Configuration doesn't follow best practices",
        evidence=[evidence],
        treatment="Add add_header directives",
        impact=["Potential clickjacking"],
        confidence=0.9
    )
    
    topology = {
        "stats": {"domains": 1, "routes": 5},
        "os_info": "Ubuntu 22.04",
        "nginx_version": "1.24.0",
        "mode": "standalone"
    }
    
    context = DiagnosisContext(
        findings=[finding],
        topology=topology,
        score=85
    )
    
    report = provider.generate(context)
    
    assert report.confidence == 0.9
    assert len(report.top_risks) == 1
    assert report.top_risks[0].finding_id == "SEC-HEAD-1"
    assert len(report.remediation_plan) == 1
    # Check if categorization worked via ID prefix
    assert report.remediation_plan[0].category == "security"
    assert report.environment_summary["nginx"] == "1.24.0"
    assert "Missing Security Headers" in report.auto_fix_candidates or any("Missing Security Headers" in c for c in report.auto_fix_candidates)

def test_generate_diagnosis_empty():
    report = generate_diagnosis([], {"stats": {}}, 100)
    assert "healthy" in report.root_cause.lower()
    assert len(report.remediation_plan) == 0
