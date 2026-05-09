from server_doctor.analyzer.node_runtime_auditor import NodeRuntimeAuditor
from server_doctor.model.server import (
    LocationBlock,
    NetworkEndpoint,
    NginxInfo,
    NodeRuntimeModel,
    ServerBlock,
    ServerModel,
)


def test_dead_local_proxy_target_emits():
    server = ServerBlock()
    server.locations.append(LocationBlock(path="/", proxy_pass="http://127.0.0.1:3000"))
    model = ServerModel(
        hostname="host",
        nginx=NginxInfo(version="1.24", config_path="/etc/nginx/nginx.conf", servers=[server]),
        node_runtime=NodeRuntimeModel(listeners=[]),
    )

    findings = NodeRuntimeAuditor(model).audit()

    assert any(f.id == "NODE-RUNTIME-004" for f in findings)


def test_listener_exists_no_dead_proxy_finding():
    server = ServerBlock()
    server.locations.append(LocationBlock(path="/", proxy_pass="http://127.0.0.1:3000"))
    model = ServerModel(
        hostname="host",
        nginx=NginxInfo(version="1.24", config_path="/etc/nginx/nginx.conf", servers=[server]),
        node_runtime=NodeRuntimeModel(
            listeners=[NetworkEndpoint(protocol="tcp", address="127.0.0.1", port=3000)]
        ),
    )

    assert not NodeRuntimeAuditor(model).audit()


def test_external_upstream_not_checked_as_local_listener():
    server = ServerBlock()
    server.locations.append(LocationBlock(path="/", proxy_pass="https://api.example.com:443"))
    model = ServerModel(
        hostname="host",
        nginx=NginxInfo(version="1.24", config_path="/etc/nginx/nginx.conf", servers=[server]),
    )

    assert not NodeRuntimeAuditor(model).audit()
