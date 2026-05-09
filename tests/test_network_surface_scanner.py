"""Tests for NetworkSurfaceScanner."""

from unittest.mock import MagicMock

from server_doctor.scanner.network_surface import NetworkSurfaceScanner


def test_scan_parses_public_and_local_endpoints(mock_ssh_connector):
    scanner = NetworkSurfaceScanner(mock_ssh_connector)

    ss_output = """tcp LISTEN 0 128 0.0.0.0:22 0.0.0.0:* users:(("sshd",pid=100,fd=3))
tcp LISTEN 0 128 127.0.0.1:3306 0.0.0.0:* users:(("mysqld",pid=200,fd=21))
udp UNCONN 0 0 0.0.0.0:53 0.0.0.0:* users:(("systemd-resolved",pid=300,fd=10))
"""
    mock_ssh_connector.run.return_value = MagicMock(success=True, stdout=ss_output)

    result = scanner.scan()
    assert len(result.endpoints) == 3

    ssh_ep = next(ep for ep in result.endpoints if ep.port == 22)
    assert ssh_ep.public_exposed is True
    assert ssh_ep.service == "ssh"

    mysql_ep = next(ep for ep in result.endpoints if ep.port == 3306)
    assert mysql_ep.public_exposed is False
    assert mysql_ep.service == "mysql"


def test_scan_parses_netstat_format_when_ss_falls_back(mock_ssh_connector):
    scanner = NetworkSurfaceScanner(mock_ssh_connector)

    netstat_output = (
        "tcp 0 0 0.0.0.0:80 0.0.0.0:* LISTEN 101/nginx\n"
        "udp 0 0 127.0.0.1:323 0.0.0.0:* 102/chronyd\n"
    )
    mock_ssh_connector.run.return_value = MagicMock(success=True, stdout=netstat_output)

    result = scanner.scan()
    assert len(result.endpoints) == 2

    http_ep = next(ep for ep in result.endpoints if ep.port == 80)
    assert http_ep.public_exposed is True
    assert http_ep.service == "http"
