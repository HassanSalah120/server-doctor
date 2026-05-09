"""Tests for OpsPostureAuditor."""

from __future__ import annotations

from server_doctor.analyzer.ops_posture_auditor import OpsPostureAuditor
from server_doctor.model.evidence import Severity
from server_doctor.model.server import DockerContainer, DockerPort, NetworkEndpoint, OpsPostureModel, ServerModel


def test_ops_posture_auditor_detects_high_risk_conditions():
    model = ServerModel(hostname="test")
    model.ops_posture = OpsPostureModel(
        backup_tools=[],
        backup_recent_files=[],
        backup_last_age_days=45.0,
        fail2ban_active=False,
        unattended_upgrades_enabled=False,
        unattended_upgrades_active=False,
        ntp_synchronized=False,
        auditd_active=False,
        apparmor_enabled=False,
        selinux_mode="disabled",
        ssh_pubkey_authentication="no",
        ssh_permit_empty_passwords="yes",
        ssh_max_auth_tries=10,
        ssh_allow_tcp_forwarding="yes",
        docker_socket_mode="666",
        docker_privileged_containers=["api"],
        docker_host_network_containers=["api"],
        docker_host_pid_containers=["api"],
        docker_root_user_containers=["api"],
        docker_no_memory_limit_containers=["api"],
        docker_no_readonly_rootfs_containers=["api"],
    )
    model.network_surface.endpoints = [
        NetworkEndpoint(protocol="tcp", address="0.0.0.0", port=22, public_exposed=True)
    ]
    model.services.docker_containers = [
        DockerContainer(
            name="api",
            image="example/api:latest",
            status="running",
            ports=[DockerPort(container_port=8080, host_ip="0.0.0.0", host_port=8080)],
        )
    ]

    findings = OpsPostureAuditor(model).audit()
    ids = {f.id for f in findings}

    assert "OPS-BACKUP-1" in ids
    assert "OPS-BACKUP-2" in ids
    assert "OPS-PATCH-1" in ids
    assert "OPS-TIME-1" in ids
    assert "OPS-SSH-1" in ids
    assert "OPS-MAC-1" in ids
    assert "OPS-SSH-2" in ids
    assert "OPS-SSH-3" in ids
    assert "OPS-SSH-4" in ids
    assert "OPS-SSH-5" in ids
    assert "OPS-DOCKER-1" in ids
    assert "OPS-DOCKER-2" in ids
    assert "OPS-DOCKER-3" in ids
    assert "OPS-DOCKER-4" in ids
    assert "OPS-DOCKER-5" in ids
    assert "OPS-DOCKER-6" in ids
    assert "OPS-DOCKER-7" in ids

    docker_priv = next(f for f in findings if f.id == "OPS-DOCKER-2")
    assert docker_priv.severity == Severity.CRITICAL

    empty_passwords = next(f for f in findings if f.id == "OPS-SSH-3")
    assert empty_passwords.severity == Severity.CRITICAL


def test_ops_posture_auditor_ignores_internal_only_root_and_writable_rootfs():
    model = ServerModel(hostname="test")
    model.ops_posture = OpsPostureModel(
        docker_root_user_containers=["db"],
        docker_no_readonly_rootfs_containers=["db"],
    )
    model.services.docker_containers = [
        DockerContainer(
            name="db",
            image="mysql:8.0",
            status="running",
            ports=[DockerPort(container_port=3306, host_ip="127.0.0.1", host_port=3306)],
        )
    ]

    findings = OpsPostureAuditor(model).audit()
    ids = {f.id for f in findings}
    assert "OPS-DOCKER-5" not in ids
    assert "OPS-DOCKER-7" not in ids


def test_ops_posture_auditor_returns_clean_when_posture_is_healthy():
    model = ServerModel(hostname="test")
    model.ops_posture = OpsPostureModel(
        backup_tools=["restic"],
        backup_recent_files=["/var/backups/nightly.tar.gz"],
        backup_last_age_days=1.0,
        fail2ban_active=True,
        unattended_upgrades_enabled=True,
        unattended_upgrades_active=True,
        ntp_synchronized=True,
        auditd_active=True,
        apparmor_enabled=True,
        selinux_mode="enforcing",
        ssh_pubkey_authentication="yes",
        ssh_permit_empty_passwords="no",
        ssh_max_auth_tries=4,
        ssh_allow_tcp_forwarding="no",
        docker_socket_mode="660",
        docker_privileged_containers=[],
        docker_host_network_containers=[],
        docker_host_pid_containers=[],
        docker_root_user_containers=[],
        docker_no_memory_limit_containers=[],
        docker_no_readonly_rootfs_containers=[],
    )

    findings = OpsPostureAuditor(model).audit()
    assert findings == []
