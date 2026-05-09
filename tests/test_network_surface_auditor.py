"""Tests for NetworkSurfaceAuditor."""

from server_doctor.analyzer.network_surface_auditor import NetworkSurfaceAuditor
from server_doctor.model.evidence import Severity
from server_doctor.model.server import (
    NetworkEndpoint,
    NetworkSurfaceModel,
    ServerModel,
)


def test_detects_insecure_and_sensitive_public_ports():
    model = ServerModel(hostname="test")
    model.services.firewall = "not_detected"
    model.network_surface = NetworkSurfaceModel(
        endpoints=[
            NetworkEndpoint(protocol="tcp", address="0.0.0.0", port=23, program="in.telnetd", service="telnet", public_exposed=True),
            NetworkEndpoint(protocol="tcp", address="0.0.0.0", port=6379, program="redis-server", service="redis", public_exposed=True),
        ]
    )

    findings = NetworkSurfaceAuditor(model).audit()
    ids = {f.id for f in findings}
    assert "NET-1" in ids
    assert "NET-2" in ids
    net2 = next(f for f in findings if f.id == "NET-2")
    assert net2.severity == Severity.CRITICAL


def test_detects_excess_public_surface():
    model = ServerModel(hostname="test")
    model.services.firewall = "present"
    model.network_surface = NetworkSurfaceModel(
        endpoints=[
            NetworkEndpoint(protocol="tcp", address="0.0.0.0", port=p, public_exposed=True)
            for p in [22, 80, 443, 8080, 8443, 9000, 9001, 9002]
        ]
    )

    findings = NetworkSurfaceAuditor(model).audit()
    assert any(f.id == "NET-3" for f in findings)


def test_detects_unknown_public_service_fingerprint():
    model = ServerModel(hostname="test")
    model.network_surface = NetworkSurfaceModel(
        endpoints=[
            NetworkEndpoint(
                protocol="tcp",
                address="0.0.0.0",
                port=5555,
                public_exposed=True,
            )
        ]
    )

    findings = NetworkSurfaceAuditor(model).audit()
    assert any(f.id == "NET-4" for f in findings)
