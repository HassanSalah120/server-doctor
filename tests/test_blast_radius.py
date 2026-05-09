import pytest
from server_doctor.ai.diagnoser import RuleBasedProvider, DiagnosisContext, DiagnosisReport
from server_doctor.model.server import ServerModel, NginxInfo, ServiceStatus, CapabilityLevel, ServerBlock, LocationBlock
from server_doctor.model.finding import Finding, Evidence, Severity

@pytest.fixture
def mock_topology():
    return ServerModel(
        hostname="test-server",
        nginx=NginxInfo(version="1.24.0", config_path="/etc/nginx/nginx.conf"),
        nginx_status=ServiceStatus(capability=CapabilityLevel.FULL)
    )

def test_blast_radius_single_finding(mock_topology):
    # Setup one server block with 2 locations and SOURCE FILES
    conf_path = "/etc/nginx/sites-available/example.conf"
    loc1 = LocationBlock(path="/api", source_file=conf_path, line_number=10)
    loc2 = LocationBlock(path="/static", source_file=conf_path, line_number=30)
    
    mock_topology.nginx.servers = [
        ServerBlock(
            server_names=["example.com"], 
            locations=[loc1, loc2], 
            listen=["80"],
            source_file=conf_path
        )
    ]
    
    provider = RuleBasedProvider()
    evidence = [Evidence(source_file=conf_path, line_number=12, excerpt="location /api {", command="")]
    finding = Finding(id="SEC-HEAD-1", severity=Severity.CRITICAL, confidence=0.9, condition="Missing HSTS", cause="Not set", evidence=evidence)
    
    context = DiagnosisContext(findings=[finding], topology=mock_topology, score=85)
    report = provider.generate(context)
    
    risk = report.top_risks[0] if report.top_risks else None
    assert risk is not None
    assert "example.com" in risk.impact
    assert "/api" in risk.impact

def test_blast_radius_global_finding(mock_topology):
    mock_topology.nginx.servers = [
        ServerBlock(server_names=["app1.com"], listen=["80"]),
        ServerBlock(server_names=["app2.com"], listen=["80"])
    ]
    
    provider = RuleBasedProvider()
    # Global finding (SSH)
    evidence = [Evidence(source_file="/etc/ssh/sshd_config", line_number=50, excerpt="PasswordAuthentication yes", command="")]
    finding = Finding(id="SEC-AUTH-1", severity=Severity.CRITICAL, confidence=1.0, condition="Password Auth Enabled", cause="SSH", evidence=evidence)
    
    context = DiagnosisContext(findings=[finding], topology=mock_topology, score=40)
    report = provider.generate(context)
    
    risk = report.top_risks[0] if report.top_risks else None
    assert risk is not None
    assert "Entire server" in risk.impact
