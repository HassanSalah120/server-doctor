"""Noise-control tests for PortAuditor orphan-port detection."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from server_doctor.checks import CheckContext
from server_doctor.checks.ports.port_auditor import ListeningPort, PortAuditor
from server_doctor.model.server import NginxInfo, ServerModel


def _ctx() -> CheckContext:
    model = ServerModel(
        hostname="test",
        nginx=NginxInfo(version="1.29.3", config_path="/etc/nginx/nginx.conf", servers=[]),
    )
    return CheckContext(model=model, ssh=None)


def test_orphan_ports_ignores_loopback_only_services():
    auditor = PortAuditor()
    context = _ctx()
    listening = [
        ListeningPort(protocol="tcp", address="127.0.0.1", port=5173, program="docker-proxy"),
        ListeningPort(protocol="tcp", address="127.0.0.1", port=8104, program="docker-proxy"),
        ListeningPort(protocol="tcp", address="::1", port=3000, program="docker-proxy"),
    ]

    findings = auditor._check_orphan_ports(listening, [], context)  # noqa: SLF001
    assert findings == []


def test_orphan_ports_still_reports_public_unproxied_ports():
    auditor = PortAuditor()
    context = _ctx()
    listening = [
        ListeningPort(protocol="tcp", address="0.0.0.0", port=9000, program="myservice"),
        ListeningPort(protocol="tcp", address="127.0.0.1", port=5173, program="docker-proxy"),
    ]

    findings = auditor._check_orphan_ports(listening, [], context)  # noqa: SLF001
    assert len(findings) == 1
    assert findings[0].id == "PORT-2"
    assert findings[0].condition.startswith("1 listening port")
