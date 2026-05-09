from server_doctor.actions.html_report import HTMLReportAction
from server_doctor.model.evidence import Evidence, Severity
from server_doctor.model.finding import Finding
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
    TLSCertificateStatus,
    TLSStatusModel,
    UpstreamProbeResult,
)
import re


def _finding(fid: str, condition: str, severity: Severity = Severity.WARNING, excerpt: str = "") -> Finding:
    return Finding(
        id=fid,
        severity=severity,
        confidence=0.9,
        condition=condition,
        cause="cause",
        evidence=[Evidence(source_file="docker", line_number=1, excerpt=excerpt or condition)],
        treatment="t",
        impact=["impact"],
    )


def test_group_findings_collapses_ngx000_cluster():
    findings = [
        _finding("NGX000-1", "Docker port 3000 is exposed", excerpt="Port Binding: 0.0.0.0:3000 -> 3000/tcp"),
        _finding("NGX000-2", "Docker port 8104 is exposed", excerpt="Port Binding: 0.0.0.0:8104 -> 8104/tcp"),
        _finding("SSH-1", "SSH password authentication is enabled"),
    ]

    grouped = HTMLReportAction._group_findings(findings)
    ids = {f.id for f in grouped}

    assert "SSH-1" in ids
    assert "NGX000-GROUP" in ids
    assert len(grouped) == 2


def test_action_plan_prioritizes_severity():
    findings = [
        _finding("SEC-1", "warning one", severity=Severity.WARNING),
        _finding("SYSTEMD-1", "Service 'x' has failed", severity=Severity.CRITICAL),
        _finding("INFO-1", "info one", severity=Severity.INFO),
    ]

    plan = HTMLReportAction._build_action_plan(findings, limit=2)
    assert len(plan) == 2
    assert plan[0]["id"] == "SYSTEMD-1"
    assert plan[0]["severity"] == "CRITICAL"


def test_action_plan_uses_certbot_playbook_command():
    findings = [
        _finding("CERTBOT-1", "Certbot renewal is failing and certificate expires in 11 day(s)", severity=Severity.CRITICAL),
    ]
    plan = HTMLReportAction._build_action_plan(findings, limit=1)
    assert "certbot renew --dry-run" in plan[0]["command"]
    assert "systemctl status certbot.service certbot.timer" in plan[0]["command"]


def test_group_findings_collapses_security_headers_cluster():
    findings = [
        _finding("SEC-HEAD-1", "Missing security headers in location '/health'"),
        _finding("SEC-HEAD-1.2", "Missing security headers in location '~ ^/(api|auth)/'"),
    ]

    grouped = HTMLReportAction._group_findings(findings)
    ids = {f.id for f in grouped}
    assert "SEC-HEADERS-GROUP" in ids
    assert len(grouped) == 1


def test_group_findings_collapses_expected_route_infos():
    findings = [
        _finding("ROUTE-1", "Route conflict (expected precedence) between '/admin/' and '/'", severity=Severity.INFO),
        _finding("ROUTE-1.2", "Route conflict (expected precedence) between '/health' and '/'", severity=Severity.INFO),
    ]
    grouped = HTMLReportAction._group_findings(findings)
    ids = {f.id for f in grouped}
    assert "ROUTE-GROUP" in ids


def test_build_traffic_flow_maps_proxy_to_container():
    model = ServerModel(
        hostname="example.com",
        nginx=NginxInfo(
            version="1.24.0",
            config_path="/etc/nginx/nginx.conf",
            servers=[
                ServerBlock(
                    server_names=["example.com"],
                    listen=["443 ssl"],
                    locations=[
                        LocationBlock(
                            path="/api",
                            proxy_pass="http://127.0.0.1:3000",
                            source_file="/etc/nginx/conf.d/default.conf",
                            line_number=10,
                        )
                    ],
                )
            ],
        ),
        services=ServicesModel(
            docker=ServiceStatus(capability=CapabilityLevel.FULL),
            docker_containers=[
                DockerContainer(
                    name="backend",
                    image="node:20",
                    status="running",
                    ports=[DockerPort(container_port=3000, host_ip="0.0.0.0", host_port=3000)],
                )
            ],
        ),
    )

    flow = HTMLReportAction._build_traffic_flow(model, ws_inventory=[])
    assert len(flow) == 1
    assert flow[0]["domain"] == "example.com"
    assert flow[0]["path"] == "/api"
    assert flow[0]["containers"] == ["backend"]
    assert flow[0]["confidence_label"] in {"MEDIUM", "HIGH"}
    assert flow[0]["unknown"] is False


def test_build_traffic_flow_marks_unknown_edges():
    model = ServerModel(
        hostname="example.com",
        nginx=NginxInfo(
            version="1.24.0",
            config_path="/etc/nginx/nginx.conf",
            servers=[
                ServerBlock(
                    server_names=["example.com"],
                    listen=["443 ssl"],
                    locations=[
                        LocationBlock(
                            path="/wss",
                            proxy_pass="http://backend_ws",
                            source_file="/etc/nginx/conf.d/default.conf",
                            line_number=11,
                        )
                    ],
                )
            ],
        ),
    )
    flow = HTMLReportAction._build_traffic_flow(model, ws_inventory=[])
    assert len(flow) == 1
    assert flow[0]["unknown"] is True
    assert flow[0]["confidence_label"] == "UNKNOWN"


def test_docker_group_filters_ingress_evidence():
    findings = [
        _finding("NGX000-1", "Docker port 5173 is exposed publicly bypassing Nginx", severity=Severity.CRITICAL, excerpt="Port Binding: 0.0.0.0:5173 -> 80/tcp"),
        _finding("NGX000-2", "Docker port 8104 is exposed publicly bypassing Nginx", severity=Severity.WARNING, excerpt="Port Binding: 0.0.0.0:8104 -> 8104/tcp"),
        _finding("NGX000-3", "Docker port 80 is exposed publicly bypassing Nginx", severity=Severity.WARNING, excerpt="Port Binding: 0.0.0.0:80 -> 80/tcp"),
    ]
    grouped = HTMLReportAction._group_findings(findings)
    group = next(f for f in grouped if f.id == "NGX000-GROUP")
    evidence_text = "\n".join(ev.excerpt for ev in group.evidence)
    assert ":80 ->" not in evidence_text


def test_effective_routing_winner_probes_prefer_exact_host():
    model = ServerModel(
        hostname="example.com",
        nginx=NginxInfo(
            version="1.24.0",
            config_path="/etc/nginx/nginx.conf",
            servers=[
                ServerBlock(
                    server_names=["_"],
                    listen=["80 default_server"],
                    locations=[LocationBlock(path="/", root="/var/www/default", source_file="/etc/nginx/default.conf", line_number=10)],
                    source_file="/etc/nginx/default.conf",
                    line_number=1,
                ),
                ServerBlock(
                    server_names=["example.com"],
                    listen=["443 ssl"],
                    locations=[LocationBlock(path="/api", proxy_pass="http://127.0.0.1:3000", source_file="/etc/nginx/example.conf", line_number=20)],
                    source_file="/etc/nginx/example.conf",
                    line_number=2,
                ),
            ],
        ),
    )
    rows = HTMLReportAction._build_effective_routing_winners(model)
    probe = next(r for r in rows if r["host"] == "example.com" and r["probe"] == "/api")
    assert probe["winner_file"].endswith("example.conf")
    assert probe["location_path"] == "/api"


def test_header_inheritance_graph_marks_overrides():
    model = ServerModel(
        hostname="example.com",
        nginx=NginxInfo(
            version="1.24.0",
            config_path="/etc/nginx/nginx.conf",
            http_headers={"X-Frame-Options": "DENY"},
            servers=[
                ServerBlock(
                    server_names=["example.com"],
                    listen=["443 ssl"],
                    headers={"X-Frame-Options": "DENY", "X-Content-Type-Options": "nosniff"},
                    locations=[
                        LocationBlock(
                            path="/api",
                            headers={"Cache-Control": "no-store"},
                            source_file="/etc/nginx/example.conf",
                            line_number=33,
                        )
                    ],
                )
            ],
        ),
    )
    graph = HTMLReportAction._build_header_inheritance_graph(model)
    assert graph
    assert graph[0]["mode"] == "override"
    assert "X-Frame-Options" in graph[0]["missing"]


def test_generated_html_has_utf8_meta_and_no_mojibake(tmp_path):
    model = ServerModel(hostname="example.com")
    out = tmp_path / "report.html"
    path = HTMLReportAction().generate(model=model, findings=[], output_path=str(out))
    content = out.read_text(encoding="utf-8")

    assert re.search(r"<head>\s*<meta charset=\"UTF-8\"", content, flags=re.IGNORECASE)
    assert "â†" not in content
    assert "ï»¿" not in content
    assert "ðŸ" not in content


def test_collect_probe_paths_includes_detected_api_ws_static():
    model = ServerModel(
        hostname="example.com",
        nginx=NginxInfo(
            version="1.24.0",
            config_path="/etc/nginx/nginx.conf",
            servers=[
                ServerBlock(
                    server_names=["example.com"],
                    listen=["443 ssl"],
                    locations=[
                        LocationBlock(path="~ ^/(api|auth)/"),
                        LocationBlock(path="/wss19"),
                        LocationBlock(path="/assets/"),
                    ],
                )
            ],
        ),
    )
    probes = HTMLReportAction._collect_probe_paths(model, ws_inventory=[])
    assert "/api" in probes
    assert "/auth" in probes
    assert "/wss19" in probes
    assert "/assets/" in probes


def test_generated_html_sidebar_scrollspy_uses_section_offsets(tmp_path):
    model = ServerModel(hostname="example.com")
    out = tmp_path / "report.html"
    HTMLReportAction().generate(model=model, findings=[], output_path=str(out))
    content = out.read_text(encoding="utf-8")

    assert "const sectionsByOffset = ()" in content
    assert ".sort((a, b) => a.el.offsetTop - b.el.offsetTop)" in content
    assert 'data-target="infrastructure"' in content
    assert 'id="report-main"' in content


def test_generated_html_includes_tls_probe_and_patch_sections(tmp_path):
    model = ServerModel(
        hostname="example.com",
        tls=TLSStatusModel(
            certificates=[
                TLSCertificateStatus(
                    path="/etc/letsencrypt/live/example/fullchain.pem",
                    issuer="CN=Let's Encrypt",
                    expires_at="May 10 12:34:56 2026 GMT",
                    days_remaining=90,
                    sans=["example.com", "www.example.com"],
                    parse_ok=True,
                )
            ]
        ),
        upstream_probes=[
            UpstreamProbeResult(
                target="127.0.0.1:3000",
                protocol="http",
                reachable=True,
                latency_ms=12.5,
                detail="http 200",
            )
        ],
    )
    findings = [
        _finding(
            "NGX000-1",
            "Docker port 3000 is exposed",
            severity=Severity.WARNING,
            excerpt="Port Binding: 0.0.0.0:3000 -> 3000/tcp",
        )
    ]
    out = tmp_path / "report.html"
    HTMLReportAction().generate(model=model, findings=findings, output_path=str(out))
    content = out.read_text(encoding="utf-8")

    assert "TLS Status" in content
    assert "Active Upstream Probes" in content
    assert "docker-compose patch snippet" in content


def test_firewall_posture_uses_default_incoming_policy():
    model = ServerModel(hostname="example.com")
    model.services.firewall_ufw_enabled = True
    model.services.firewall_ufw_default_incoming = "deny"
    model.services.firewall_rules = []
    status, evidence = HTMLReportAction._classify_firewall_posture(model, port=3000, proto="tcp")
    assert status == "BLOCKED"
    assert "default incoming policy" in evidence


def test_exposure_map_downgrades_when_firewall_blocked():
    model = ServerModel(hostname="example.com")
    model.services.firewall_ufw_enabled = True
    model.services.firewall_ufw_default_incoming = "deny"
    model.services.docker_containers = [
        DockerContainer(
            name="vite",
            image="node:20",
            status="running",
            ports=[DockerPort(container_port=5173, host_ip="0.0.0.0", host_port=5173)],
        )
    ]
    rows = HTMLReportAction._build_exposure_map(model)
    assert rows
    assert rows[0]["severity"] == "WARNING"
    assert "blocked today but published" in rows[0]["reason"].lower()


def test_exposure_map_marks_ingress_443_as_expected_info():
    model = ServerModel(hostname="example.com")
    model.services.docker_containers = [
        DockerContainer(
            name="chatduel-nginx",
            image="nginx:alpine",
            status="running",
            ports=[DockerPort(container_port=443, host_ip="0.0.0.0", host_port=443)],
        )
    ]
    rows = HTMLReportAction._build_exposure_map(model)
    assert rows
    assert rows[0]["severity"] == "INFO"
    assert "Expected ingress exposure" in rows[0]["reason"]
    assert rows[0]["proxied_display"] == "N/A (ingress)"
