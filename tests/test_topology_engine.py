from server_doctor.engine.topology import build_topology_snapshot, diff_topology
from server_doctor.model.server import (
    CapabilityLevel,
    DockerContainer,
    DockerPort,
    LocationBlock,
    NginxInfo,
    ServerBlock,
    ServerModel,
    ServiceStatus,
    ServicesModel,
)


def _model_with_routes(order: str) -> ServerModel:
    if order == "ab":
        locations = [
            LocationBlock(path="/", proxy_pass="http://127.0.0.1:3000"),
            LocationBlock(path="/api", proxy_pass="http://127.0.0.1:8104"),
        ]
    else:
        locations = [
            LocationBlock(path="/api", proxy_pass="http://127.0.0.1:8104"),
            LocationBlock(path="/", proxy_pass="http://127.0.0.1:3000"),
        ]

    return ServerModel(
        hostname="example.com",
        nginx=NginxInfo(
            version="1.24.0",
            config_path="/etc/nginx/nginx.conf",
            servers=[ServerBlock(server_names=["example.com"], listen=["443 ssl"], locations=locations)],
        ),
        services=ServicesModel(
            docker=ServiceStatus(capability=CapabilityLevel.FULL),
            docker_containers=[
                DockerContainer(
                    name="api",
                    image="node:20",
                    status="running",
                    ports=[
                        DockerPort(container_port=3000, host_ip="0.0.0.0", host_port=3000),
                        DockerPort(container_port=8104, host_ip="0.0.0.0", host_port=8104),
                    ],
                )
            ],
        ),
    )


def test_topology_snapshot_is_deterministic():
    snap1 = build_topology_snapshot(_model_with_routes("ab"))
    snap2 = build_topology_snapshot(_model_with_routes("ba"))

    assert snap1["signature"] == snap2["signature"]
    assert snap1["route_keys"] == snap2["route_keys"]
    assert snap1["binding_keys"] == snap2["binding_keys"]


def test_topology_diff_detects_changes():
    snap1 = build_topology_snapshot(_model_with_routes("ab"))
    model2 = _model_with_routes("ab")
    model2.nginx.servers[0].locations.append(LocationBlock(path="/health", proxy_pass="http://127.0.0.1:3000"))
    snap2 = build_topology_snapshot(model2)

    delta = diff_topology(snap1, snap2)
    assert delta["has_previous"] is True
    assert delta["signature_changed"] is True
    assert any("/health" in key for key in delta["added_routes"])
