from types import SimpleNamespace

from server_doctor.model.server import NginxInfo, LocationBlock, ServerBlock, UpstreamBlock
from server_doctor.scanner.upstream_probe import UpstreamProbeScanner


class _FakeSSH:
    def __init__(self, outputs: dict[str, str]) -> None:
        self.outputs = outputs

    def run(self, cmd: str, timeout: int = 0):
        for needle, out in self.outputs.items():
            if needle in cmd:
                return SimpleNamespace(success=True, stdout=out)
        return SimpleNamespace(success=True, stdout="")


def test_upstream_probe_marks_unknown_for_dns_without_exec():
    ssh = _FakeSSH(
        {
            "docker exec abc123 sh -lc 'echo ok'": "",
        }
    )
    scanner = UpstreamProbeScanner(ssh)
    nginx = NginxInfo(
        version="1.24.0",
        config_path="/etc/nginx/nginx.conf",
        container_id="abc123",
        servers=[
            ServerBlock(
                server_names=["example.com"],
                locations=[LocationBlock(path="/api", proxy_pass="http://backend:3000")],
            )
        ],
    )
    probes = scanner.scan(nginx, enabled=True)
    assert probes
    assert probes[0].scope == "unknown"
    assert probes[0].status == "UNKNOWN"


def test_upstream_probe_reports_open_with_layered_data():
    ssh = _FakeSSH(
        {
            "echo ok": "ok",
            "nc -z -w 2 127.0.0.1 3000": "TCP_OK 0.010",
            "curl -sk -o /dev/null -w '%{http_code} %{time_total}' --max-time 2 http://127.0.0.1:3000/": "200 0.020",
            "Connection: Upgrade": "101",
        }
    )
    scanner = UpstreamProbeScanner(ssh)
    nginx = NginxInfo(
        version="1.24.0",
        config_path="/etc/nginx/nginx.conf",
        servers=[
            ServerBlock(
                server_names=["example.com"],
                locations=[LocationBlock(path="/wss", proxy_pass="http://127.0.0.1:3000")],
            )
        ],
    )
    probes = scanner.scan(nginx, enabled=True)
    probe = probes[0]
    assert probe.status == "OPEN"
    assert probe.tcp_ok is True
    assert probe.http_code == 200
    assert probe.ws_status == "101"


def test_upstream_probe_prefers_ws_route_path_for_handshake():
    ssh = _FakeSSH(
        {
            "nc -z -w 2 127.0.0.1 3000": "TCP_OK 0.010",
            "http://127.0.0.1:3000/ ": "404 0.020",
            "http://127.0.0.1:3000/wss19": "101",
        }
    )
    scanner = UpstreamProbeScanner(ssh)
    nginx = NginxInfo(
        version="1.24.0",
        config_path="/etc/nginx/nginx.conf",
        servers=[
            ServerBlock(
                server_names=["example.com"],
                locations=[LocationBlock(path="/wss19", proxy_pass="http://127.0.0.1:3000")],
            )
        ],
    )
    probes = scanner.scan(nginx, enabled=True)
    probe = probes[0]
    assert probe.ws_code == 101
    assert probe.ws_status == "101"
    assert probe.status == "OPEN"


def test_upstream_probe_records_ws_timeout_status():
    ssh = _FakeSSH(
        {
            "nc -z -w 2 127.0.0.1 3000": "TCP_OK 0.010",
            "curl -sk -o /dev/null -w '%{http_code} %{time_total}' --max-time 2 http://127.0.0.1:3000/": "200 0.020",
            "Connection: Upgrade": "timeout",
        }
    )
    scanner = UpstreamProbeScanner(ssh)
    nginx = NginxInfo(
        version="1.24.0",
        config_path="/etc/nginx/nginx.conf",
        servers=[
            ServerBlock(
                server_names=["example.com"],
                locations=[LocationBlock(path="/wss", proxy_pass="http://127.0.0.1:3000")],
            )
        ],
    )
    probes = scanner.scan(nginx, enabled=True)
    probe = probes[0]
    assert probe.ws_status == "timeout"
    assert "timeout" in (probe.ws_detail or "")


def test_upstream_probe_applies_ws_probe_for_named_upstream_routes():
    ssh = _FakeSSH(
        {
            "docker exec abc123 sh -lc 'echo ok'": "ok",
            "nc -z -w 2 backend 8104": "TCP_OK 0.010",
            "curl -sk -o /dev/null -w '%{http_code} %{time_total}' --max-time 2 http://backend:8104/": "404 0.020",
            "wss19": "101",
        }
    )
    scanner = UpstreamProbeScanner(ssh)
    nginx = NginxInfo(
        version="1.24.0",
        config_path="/etc/nginx/nginx.conf",
        container_id="abc123",
        upstreams=[UpstreamBlock(name="backend_ws", servers=["backend:8104"])],
        servers=[
            ServerBlock(
                server_names=["example.com"],
                locations=[LocationBlock(path="/wss19", proxy_pass="http://backend_ws")],
            )
        ],
    )
    probes = scanner.scan(nginx, enabled=True)
    probe = probes[0]
    assert probe.ws_status == "101"
    assert probe.ws_code == 101
    assert probe.ws_path == "/wss19"


def test_upstream_probe_reports_http_404_reason_for_ws_path():
    ssh = _FakeSSH(
        {
            "docker exec abc123 sh -lc 'echo ok'": "ok",
            "nc -z -w 2 backend 8104": "TCP_OK 0.010",
            "curl -sk -o /dev/null -w '%{http_code} %{time_total}' --max-time 2 http://backend:8104/": "404 0.020",
            "wss19": "404",
        }
    )
    scanner = UpstreamProbeScanner(ssh)
    nginx = NginxInfo(
        version="1.24.0",
        config_path="/etc/nginx/nginx.conf",
        container_id="abc123",
        upstreams=[UpstreamBlock(name="backend_ws", servers=["backend:8104"])],
        servers=[
            ServerBlock(
                server_names=["example.com"],
                locations=[LocationBlock(path="/wss19", proxy_pass="http://backend_ws")],
            )
        ],
    )
    probe = scanner.scan(nginx, enabled=True)[0]
    assert probe.ws_status == "404"
    assert "HTTP 404" in (probe.ws_detail or "")
    assert "wrong WS route" in (probe.ws_detail or "")


def test_upstream_probe_reports_http_200_non_ws_reason():
    ssh = _FakeSSH(
        {
            "docker exec abc123 sh -lc 'echo ok'": "ok",
            "nc -z -w 2 backend 8104": "TCP_OK 0.010",
            "curl -sk -o /dev/null -w '%{http_code} %{time_total}' --max-time 2 http://backend:8104/": "200 0.020",
            "wss19": "200",
        }
    )
    scanner = UpstreamProbeScanner(ssh)
    nginx = NginxInfo(
        version="1.24.0",
        config_path="/etc/nginx/nginx.conf",
        container_id="abc123",
        upstreams=[UpstreamBlock(name="backend_ws", servers=["backend:8104"])],
        servers=[
            ServerBlock(
                server_names=["example.com"],
                locations=[LocationBlock(path="/wss19", proxy_pass="http://backend_ws")],
            )
        ],
    )
    probe = scanner.scan(nginx, enabled=True)[0]
    assert probe.ws_status == "200"
    assert "not WebSocket" in (probe.ws_detail or "")


def test_upstream_probe_refines_handshake_error_using_http_context():
    ssh = _FakeSSH(
        {
            "docker exec abc123 sh -lc 'echo ok'": "ok",
            "nc -z -w 2 backend 8104": "TCP_OK 0.010",
            "curl -sk -o /dev/null -w '%{http_code} %{time_total}' --max-time 2 http://backend:8104/": "404 0.020",
            "Connection: Upgrade": "fail",
        }
    )
    scanner = UpstreamProbeScanner(ssh)
    nginx = NginxInfo(
        version="1.24.0",
        config_path="/etc/nginx/nginx.conf",
        container_id="abc123",
        upstreams=[UpstreamBlock(name="backend_ws", servers=["backend:8104"])],
        servers=[
            ServerBlock(
                server_names=["example.com"],
                locations=[LocationBlock(path="/wss19", proxy_pass="http://backend_ws")],
            )
        ],
    )
    probe = scanner.scan(nginx, enabled=True)[0]
    assert probe.ws_status == "handshake_error"
    assert "likely wrong WS path" in (probe.ws_detail or "")
