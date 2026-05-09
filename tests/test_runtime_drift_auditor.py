from server_doctor.analyzer.runtime_drift_auditor import RuntimeDriftAuditor
from server_doctor.model.evidence import Severity
from server_doctor.model.server import (
    LocationBlock,
    NetworkEndpoint,
    NetworkSurfaceModel,
    NginxInfo,
    ServerBlock,
    ServerModel,
    UpstreamBlock,
)


def test_runtime_drift_flags_unbacked_local_proxy_target():
    model = ServerModel(
        hostname="example.com",
        nginx=NginxInfo(
            version="1.24.0",
            config_path="/etc/nginx/nginx.conf",
            servers=[
                ServerBlock(
                    server_names=["example.com"],
                    locations=[
                        LocationBlock(
                            path="/api",
                            proxy_pass="http://127.0.0.1:3999",
                            source_file="/etc/nginx/conf.d/default.conf",
                            line_number=42,
                        )
                    ],
                )
            ],
        ),
        network_surface=NetworkSurfaceModel(endpoints=[]),
    )

    findings = RuntimeDriftAuditor(model).audit()
    ids = {f.id for f in findings}
    assert "DRIFT-1" in ids


def test_runtime_drift_accepts_backed_local_proxy_target():
    model = ServerModel(
        hostname="example.com",
        nginx=NginxInfo(
            version="1.24.0",
            config_path="/etc/nginx/nginx.conf",
            servers=[
                ServerBlock(
                    server_names=["example.com"],
                    locations=[LocationBlock(path="/api", proxy_pass="http://127.0.0.1:3999")],
                )
            ],
        ),
        network_surface=NetworkSurfaceModel(
            endpoints=[NetworkEndpoint(protocol="tcp", address="127.0.0.1", port=3999)]
        ),
    )

    findings = RuntimeDriftAuditor(model).audit()
    ids = {f.id for f in findings}
    assert "DRIFT-1" not in ids


def test_runtime_drift_flags_unused_upstream():
    model = ServerModel(
        hostname="example.com",
        nginx=NginxInfo(
            version="1.24.0",
            config_path="/etc/nginx/nginx.conf",
            upstreams=[
                UpstreamBlock(
                    name="backend_unused",
                    servers=["127.0.0.1:3001"],
                    source_file="/etc/nginx/conf.d/upstreams.conf",
                    line_number=10,
                )
            ],
            servers=[
                ServerBlock(
                    server_names=["example.com"],
                    locations=[LocationBlock(path="/", proxy_pass="http://127.0.0.1:3000")],
                )
            ],
        ),
    )

    findings = RuntimeDriftAuditor(model).audit()
    ids = {f.id for f in findings}
    assert "DRIFT-2" in ids


def test_runtime_drift_handles_unix_socket_target():
    model = ServerModel(
        hostname="example.com",
        nginx=NginxInfo(
            version="1.24.0",
            config_path="/etc/nginx/nginx.conf",
            servers=[
                ServerBlock(
                    server_names=["example.com"],
                    locations=[LocationBlock(path="~ \\.php$", fastcgi_pass="unix:/run/php/php8.2-fpm.sock")],
                )
            ],
        ),
    )
    findings = RuntimeDriftAuditor(model).audit()
    drift = next((f for f in findings if f.id == "DRIFT-1"), None)
    assert drift is not None


def test_runtime_drift_unused_upstream_downgrades_on_variable_proxy_pass():
    model = ServerModel(
        hostname="example.com",
        nginx=NginxInfo(
            version="1.24.0",
            config_path="/etc/nginx/nginx.conf",
            upstreams=[UpstreamBlock(name="backend_unused", servers=["127.0.0.1:3001"])],
            servers=[
                ServerBlock(
                    server_names=["example.com"],
                    locations=[LocationBlock(path="/", proxy_pass="http://$upstream_name")],
                )
            ],
        ),
    )
    findings = RuntimeDriftAuditor(model).audit()
    drift2 = next((f for f in findings if f.id == "DRIFT-2"), None)
    assert drift2 is not None
    assert drift2.severity == Severity.INFO
