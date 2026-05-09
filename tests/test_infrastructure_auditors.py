"""Tests for infrastructure-focused auditors."""

from server_doctor.analyzer.firewall_auditor import FirewallAuditor
from server_doctor.analyzer.mysql_auditor import MySQLAuditor
from server_doctor.analyzer.security_baseline_auditor import SecurityBaselineAuditor
from server_doctor.analyzer.telemetry_auditor import TelemetryAuditor
from server_doctor.analyzer.docker_auditor import DockerAuditor
from server_doctor.model.evidence import Severity
from server_doctor.model.server import (
    CapabilityLevel,
    DockerContainer,
    DockerPort,
    DiskUsage,
    LocationBlock,
    NginxInfo,
    ServerBlock,
    ServerModel,
    SecurityBaselineModel,
    ServiceState,
    ServiceStatus,
    TelemetryModel,
)


def test_mysql_public_exposure_detected():
    model = ServerModel(hostname="test")
    model.services.mysql = ServiceStatus(
        capability=CapabilityLevel.FULL,
        state=ServiceState.RUNNING,
        listening_ports=[3306],
    )
    model.services.mysql_bind_addresses = ["0.0.0.0"]
    model.services.firewall = "not_detected"

    findings = MySQLAuditor(model).audit()
    assert any(f.id == "MYSQL-1" for f in findings)
    mysql_finding = next(f for f in findings if f.id == "MYSQL-1")
    assert mysql_finding.severity == Severity.CRITICAL


def test_firewall_missing_detected_for_public_service():
    model = ServerModel(hostname="test")
    model.services.firewall = "not_detected"
    model.nginx = NginxInfo(
        version="1.24.0",
        config_path="/etc/nginx/nginx.conf",
        servers=[
            ServerBlock(
                server_names=["example.com"],
                listen=["80"],
                source_file="/etc/nginx/sites-enabled/example.com",
                line_number=1,
            )
        ],
    )

    findings = FirewallAuditor(model).audit()
    assert any(f.id == "FIREWALL-1" for f in findings)


def test_telemetry_pressure_checks():
    model = ServerModel(hostname="test")
    model.telemetry = TelemetryModel(
        cpu_cores=2,
        load_1=5.0,
        load_5=4.0,
        load_15=3.0,
        mem_total_mb=1000,
        mem_available_mb=60,
        swap_total_mb=1000,
        swap_free_mb=20,
        disks=[
            DiskUsage(
                mount="/",
                total_gb=10.0,
                used_gb=9.7,
                used_percent=97.0,
                inode_total=1_000_000,
                inode_used_percent=96.0,
            )
        ],
    )

    findings = TelemetryAuditor(model).audit()
    ids = {f.id for f in findings}
    assert "HOST-CPU-1" in ids
    assert "HOST-MEM-1" in ids
    assert "HOST-SWAP-1" in ids
    assert "HOST-DISK-1" in ids
    assert "HOST-DISK-2" in ids


def test_security_baseline_ssh_and_patch_checks():
    model = ServerModel(hostname="test")
    model.security_baseline = SecurityBaselineModel(
        package_manager="apt",
        ssh_permit_root_login="yes",
        ssh_password_authentication="yes",
        pending_updates_total=123,
        pending_security_updates=12,
        reboot_required=True,
    )

    findings = SecurityBaselineAuditor(model).audit()
    ids = {f.id for f in findings}
    assert "SSH-1" in ids
    assert "SSH-2" in ids
    assert "PATCH-1" in ids
    assert "PATCH-3" in ids
    patch1 = next(f for f in findings if f.id == "PATCH-1")
    assert "APT" in patch1.condition


def test_security_baseline_patch2_mentions_package_manager_scope():
    model = ServerModel(hostname="test")
    model.security_baseline = SecurityBaselineModel(
        package_manager="dnf",
        pending_updates_total=77,
        pending_security_updates=0,
    )

    findings = SecurityBaselineAuditor(model).audit()
    patch2 = next(f for f in findings if f.id == "PATCH-2")
    assert "DNF" in patch2.condition
    assert "host OS package updates" in patch2.cause


def test_docker_dev_port_public_without_firewall_is_critical():
    model = ServerModel(hostname="test")
    model.services.docker = ServiceStatus(capability=CapabilityLevel.FULL, state=ServiceState.RUNNING)
    model.services.firewall = "not_detected"
    model.services.docker_containers = [
        DockerContainer(
            name="vite-frontend",
            image="node:20",
            status="running",
            ports=[DockerPort(container_port=5173, host_ip="0.0.0.0", host_port=5173)],
        )
    ]

    findings = DockerAuditor(model).audit()
    exposed = [f for f in findings if "5173" in f.condition]
    assert exposed
    assert exposed[0].severity == Severity.CRITICAL


def test_docker_public_proxied_non_ingress_is_warning():
    model = ServerModel(
        hostname="test",
        nginx=NginxInfo(
            version="1.24.0",
            config_path="/etc/nginx/nginx.conf",
            servers=[
                ServerBlock(
                    server_names=["example.com"],
                    listen=["443 ssl"],
                    locations=[LocationBlock(path="/api", proxy_pass="http://127.0.0.1:3000")],
                )
            ],
        ),
    )
    model.services.docker = ServiceStatus(capability=CapabilityLevel.FULL, state=ServiceState.RUNNING)
    model.services.docker_containers = [
        DockerContainer(
            name="api",
            image="node:20",
            status="running",
            ports=[DockerPort(container_port=3000, host_ip="0.0.0.0", host_port=3000)],
        )
    ]

    findings = DockerAuditor(model).audit()
    proxied_public = [f for f in findings if f.id == "DOCKER-3"]
    assert proxied_public
    assert proxied_public[0].severity == Severity.WARNING


def test_docker_ingress_https_on_nginx_container_is_not_reported_as_finding():
    model = ServerModel(hostname="test")
    model.services.docker = ServiceStatus(capability=CapabilityLevel.FULL, state=ServiceState.RUNNING)
    model.services.docker_containers = [
        DockerContainer(
            name="edge-nginx",
            image="nginx:alpine",
            status="running",
            ports=[DockerPort(container_port=443, host_ip="0.0.0.0", host_port=443)],
        )
    ]
    model.nginx = NginxInfo(
        version="1.24.0",
        config_path="/etc/nginx/nginx.conf",
        servers=[ServerBlock(server_names=["example.com"], listen=["443 ssl"], locations=[LocationBlock(path="/", proxy_pass="http://127.0.0.1:443")])],
    )
    findings = DockerAuditor(model).audit()
    info = [f for f in findings if f.id == "DOCKER-3"]
    assert not info


def test_docker_non_ingress_https_on_443_is_warning():
    model = ServerModel(hostname="test")
    model.services.docker = ServiceStatus(capability=CapabilityLevel.FULL, state=ServiceState.RUNNING)
    model.services.docker_containers = [
        DockerContainer(
            name="custom-app",
            image="node:20",
            status="running",
            ports=[DockerPort(container_port=443, host_ip="0.0.0.0", host_port=443)],
        )
    ]
    model.nginx = NginxInfo(
        version="1.24.0",
        config_path="/etc/nginx/nginx.conf",
        servers=[ServerBlock(server_names=["example.com"], listen=["443 ssl"], locations=[LocationBlock(path="/", proxy_pass="http://127.0.0.1:443")])],
    )
    findings = DockerAuditor(model).audit()
    warn = [f for f in findings if f.id == "DOCKER-5"]
    assert warn
    assert warn[0].severity == Severity.WARNING


def test_docker_published_port_blocked_by_firewall_is_downgraded():
    model = ServerModel(hostname="test")
    model.services.docker = ServiceStatus(capability=CapabilityLevel.FULL, state=ServiceState.RUNNING)
    model.services.firewall_ufw_enabled = True
    model.services.firewall_ufw_default_incoming = "deny"
    model.services.firewall_rules = []
    model.services.docker_containers = [
        DockerContainer(
            name="vite-frontend",
            image="node:20",
            status="running",
            ports=[DockerPort(container_port=5173, host_ip="0.0.0.0", host_port=5173)],
        )
    ]

    findings = DockerAuditor(model).audit()
    exposed = [f for f in findings if "5173" in f.condition]
    assert exposed
    assert exposed[0].severity == Severity.WARNING
    assert "blocked today but published" in exposed[0].cause.lower()
