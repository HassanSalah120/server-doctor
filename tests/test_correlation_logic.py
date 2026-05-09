import pytest
from dataclasses import dataclass
from server_doctor.analyzer.finding_correlation import CorrelationEngine
from server_doctor.model.finding import Finding, Evidence, Severity
from server_doctor.model.server import (
    ServerModel, NginxInfo, ServiceStatus, CapabilityLevel, 
    ServerBlock, LocationBlock, ServicesModel, DockerContainer, DockerPort, 
    NetworkSurfaceModel, NetworkEndpoint
)

@pytest.fixture
def mock_topology():
    return ServerModel(
        hostname="test-server",
        nginx=NginxInfo(version="1.24.0", config_path="/etc/nginx/nginx.conf"),
        nginx_status=ServiceStatus(capability=CapabilityLevel.FULL)
    )

def test_header_inheritance_correlation(mock_topology):
    evidence = [Evidence(source_file="/etc/nginx/nginx.conf", line_number=10, excerpt="location / {", command="")]
    findings = [
        Finding(id="SEC-HEAD-1", severity=Severity.WARNING, confidence=0.9, condition="Missing HSTS", cause="Not set", evidence=evidence),
        Finding(id="SEC-HEAD-1", severity=Severity.WARNING, confidence=0.9, condition="Missing HSTS", cause="Not set", evidence=evidence),
        Finding(id="SEC-HEAD-1", severity=Severity.WARNING, confidence=0.9, condition="Missing HSTS", cause="Not set", evidence=evidence),
        Finding(id="SEC-HEAD-1", severity=Severity.WARNING, confidence=0.9, condition="Missing HSTS", cause="Not set", evidence=evidence),
        Finding(id="SEC-HEAD-1", severity=Severity.WARNING, confidence=0.9, condition="Missing HSTS", cause="Not set", evidence=evidence),
    ]
    engine = CorrelationEngine(findings, mock_topology)
    correlations = engine.correlate()
    
    c = next((x for x in correlations if x.correlation_id == "header-inheritance-broken"), None)
    assert c is not None

def test_unintended_exposure_correlation(mock_topology):
    # Fix the test to match network_surface
    mock_topology.network_surface = NetworkSurfaceModel(endpoints=[
        NetworkEndpoint(protocol="tcp", address="0.0.0.0", port=3306, public_exposed=True),
    ])
    mock_topology.nginx.servers = [
        ServerBlock(listen=["80", "443 ssl"])
    ]
    
    findings = [] 
    engine = CorrelationEngine(findings, mock_topology)
    correlations = engine.correlate()
    
    c = next((x for x in correlations if x.correlation_id == "unintended-exposure-risk"), None)
    assert c is not None

def test_tls_posture_correlation(mock_topology):
    mock_topology.hostname = "docker-app-01"
    evidence = [Evidence(source_file="/etc/nginx/nginx.conf", line_number=10, excerpt="ssl_protocols TLSv1;", command="")]
    findings = [
        Finding(id="SEC-TLS-1", severity=Severity.WARNING, confidence=0.9, condition="TLS 1.0 enabled", cause="Old", evidence=evidence),
    ]
    engine = CorrelationEngine(findings, mock_topology)
    correlations = engine.correlate()
    
    c = next((x for x in correlations if x.correlation_id == "ingress-tls-posture-risk"), None)
    assert c is not None


def test_full_compromise_chain(mock_topology):
    # create findings that satisfy the new chain rule
    common_evidence = [Evidence(source_file="/etc/nginx/nginx.conf", line_number=1, excerpt="", command="")]
    f1 = Finding(id="NGX-SENS-1", severity=Severity.WARNING, confidence=0.9, condition="Sensitive path '/admin' exposed", cause="", evidence=common_evidence)
    f2 = Finding(id="LARAVEL-1", severity=Severity.CRITICAL, confidence=0.9, condition="APP_DEBUG enabled", cause="", evidence=common_evidence)
    f3 = Finding(id="NGX-SEC-3", severity=Severity.WARNING, confidence=0.9, condition="Missing dotfile protection", cause="", evidence=common_evidence)
    f4 = Finding(id="FIREWALL-1", severity=Severity.WARNING, confidence=0.9, condition="No firewall", cause="", evidence=common_evidence)
    findings = [f1, f2, f3, f4]
    engine = CorrelationEngine(findings, mock_topology)
    correlations = engine.correlate()
    c = next((x for x in correlations if x.correlation_id == "full-compromise-chain"), None)
    assert c is not None
    assert c.severity == "critical"
