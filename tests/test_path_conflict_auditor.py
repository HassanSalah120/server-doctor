from server_doctor.analyzer.path_conflict_auditor import PathConflictAuditor
from server_doctor.model.server import LocationBlock, NginxInfo, ServerBlock, ServerModel


def test_path_conflict_detects_prefix_overlap():
    model = ServerModel(
        hostname="example.com",
        nginx=NginxInfo(
            version="1.24.0",
            config_path="/etc/nginx/nginx.conf",
            servers=[
                ServerBlock(
                    server_names=["example.com"],
                    locations=[
                        LocationBlock(path="/api", source_file="/etc/nginx/conf.d/default.conf", line_number=10),
                        LocationBlock(path="/api/", source_file="/etc/nginx/conf.d/default.conf", line_number=20),
                    ],
                )
            ],
        ),
    )
    findings = PathConflictAuditor(model).audit()
    assert any(f.id == "ROUTE-1" for f in findings)
    assert any(f.severity.value == "critical" for f in findings)


def test_path_conflict_detects_websocket_regex_capture():
    model = ServerModel(
        hostname="example.com",
        nginx=NginxInfo(
            version="1.24.0",
            config_path="/etc/nginx/nginx.conf",
            servers=[
                ServerBlock(
                    server_names=["example.com"],
                    locations=[
                        LocationBlock(path="~ ^/(wss|socket)", source_file="/etc/nginx/conf.d/default.conf", line_number=5),
                        LocationBlock(path="/wss19", source_file="/etc/nginx/conf.d/default.conf", line_number=50),
                    ],
                )
            ],
        ),
    )
    findings = PathConflictAuditor(model).audit()
    assert any(f.id == "ROUTE-2" for f in findings)


def test_path_conflict_warns_when_shadow_changes_target():
    model = ServerModel(
        hostname="example.com",
        nginx=NginxInfo(
            version="1.24.0",
            config_path="/etc/nginx/nginx.conf",
            servers=[
                ServerBlock(
                    server_names=["example.com"],
                    locations=[
                        LocationBlock(path="/api", proxy_pass="http://127.0.0.1:3000"),
                        LocationBlock(path="/api/", proxy_pass="http://127.0.0.1:8104"),
                    ],
                )
            ],
        ),
    )
    findings = PathConflictAuditor(model).audit()
    route = next(f for f in findings if f.id == "ROUTE-1")
    assert route.severity.value == "warning"


def test_path_conflict_no_finding_for_disjoint_paths():
    model = ServerModel(
        hostname="example.com",
        nginx=NginxInfo(
            version="1.24.0",
            config_path="/etc/nginx/nginx.conf",
            servers=[
                ServerBlock(
                    server_names=["example.com"],
                    locations=[
                        LocationBlock(path="/api"),
                        LocationBlock(path="/assets/"),
                    ],
                )
            ],
        ),
    )
    findings = PathConflictAuditor(model).audit()
    assert not findings


def test_path_conflict_health_exact_return_is_not_broken():
    model = ServerModel(
        hostname="example.com",
        nginx=NginxInfo(
            version="1.24.0",
            config_path="/etc/nginx/nginx.conf",
            servers=[
                ServerBlock(
                    server_names=["example.com"],
                    locations=[
                        LocationBlock(path="= /health", return_directive="200 ok"),
                        LocationBlock(path="/health/", proxy_pass="http://127.0.0.1:3000"),
                    ],
                )
            ],
        ),
    )
    findings = PathConflictAuditor(model).audit()
    route = next(f for f in findings if f.id == "ROUTE-1")
    assert route.severity.value != "critical"


def test_path_conflict_benign_prefix_overlap_is_skipped():
    """Expected precedence (like / and /admin/) should not be reported."""
    model = ServerModel(
        hostname="example.com",
        nginx=NginxInfo(
            version="1.24.0",
            config_path="/etc/nginx/nginx.conf",
            servers=[
                ServerBlock(
                    server_names=["example.com"],
                    locations=[
                        LocationBlock(path="/", proxy_pass="http://127.0.0.1:3000"),
                        LocationBlock(path="/admin/", proxy_pass="http://127.0.0.1:8104"),
                    ],
                )
            ],
        ),
    )
    findings = PathConflictAuditor(model).audit()
    # Benign expected precedence should not create findings
    assert not findings
