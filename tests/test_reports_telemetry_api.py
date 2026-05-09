from server_doctor.web.routes.reports import (
    _extract_logs,
    _extract_resources,
    _extract_support_pack,
    _extract_service_health,
    _extract_telemetry,
    _extract_topology,
)


def test_extract_telemetry_keeps_stable_cpu_shape_when_cores_missing() -> None:
    out = _extract_telemetry(
        {
            "telemetry": {
                "cpu_cores": None,
                "load_1": None,
                "mem_total_mb": 4096,
                "mem_available_mb": 2048,
            }
        }
    )

    assert out["has_data"] is True
    assert out["cpu"] == {
        "cores": None,
        "load_1": None,
        "load_5": None,
        "load_15": None,
        "usage_percent": None,
        "status": "unknown",
    }
    assert out["memory"]["used_percent"] == 50


def test_extract_telemetry_keeps_cores_even_without_load() -> None:
    out = _extract_telemetry(
        {
            "telemetry": {
                "cpu_cores": 2,
                "load_1": None,
            }
        }
    )

    assert out["cpu"]["cores"] == 2
    assert out["cpu"]["usage_percent"] is None
    assert out["cpu"]["status"] == "unknown"


def test_extract_telemetry_uses_load_for_cpu_usage() -> None:
    out = _extract_telemetry(
        {
            "telemetry": {
                "cpu_cores": 4,
                "load_1": 2.0,
                "load_5": 1.26,
                "load_15": 1.04,
            }
        }
    )

    assert out["cpu"] == {
        "cores": 4,
        "load_1": 2.0,
        "load_5": 1.26,
        "load_15": 1.04,
        "usage_percent": 50,
        "status": "healthy",
    }


def test_extract_telemetry_filters_overlay_disks() -> None:
    out = _extract_telemetry(
        {
            "telemetry": {
                "cpu_cores": 2,
                "disks": [
                    {
                        "mount": "/var/lib/docker/overlay2/abc/merged",
                        "total_gb": 10,
                        "used_gb": 1,
                        "used_percent": 10,
                    },
                    {
                        "mount": "/",
                        "total_gb": 100,
                        "used_gb": 60,
                        "used_percent": 60,
                    },
                ],
            }
        }
    )

    assert len(out["disks"]) == 1
    assert out["disks"][0]["mount"] == "/"


def test_extract_service_health_reads_systemd_substate_field() -> None:
    out = _extract_service_health(
        {
            "runtime": {
                "systemd_services": [
                    {
                        "name": "containerd.service",
                        "state": "active",
                        "substate": "running",
                        "restart_count": 2,
                        "ports": [80, 443],
                    }
                ]
            }
        }
    )

    assert out == [
        {
            "name": "containerd.service",
            "state": "active",
            "sub_state": "running",
            "restart_count": 2,
            "health": "healthy",
            "ports": [80, 443],
        }
    ]


def test_extract_service_health_reads_docker_status_field() -> None:
    out = _extract_service_health(
        {
            "services": {
                "docker_containers": [
                    {
                        "name": "chatduel-backend",
                        "status": "running",
                        "restart_count": 1,
                    }
                ]
            }
        }
    )

    assert out == [
        {
            "name": "chatduel-backend",
            "state": "running",
            "restart_count": 1,
            "health": "healthy",
            "ports": [],
            "type": "docker",
        }
    ]


def test_extract_service_health_skips_systemd_exited_noise() -> None:
    out = _extract_service_health(
        {
            "runtime": {
                "systemd_services": [
                    {"name": "cloud-init.service", "state": "active", "substate": "exited", "restart_count": 0},
                    {"name": "containerd.service", "state": "active", "substate": "running", "restart_count": 0},
                ]
            }
        }
    )

    assert len(out) == 1
    assert out[0]["name"] == "containerd.service"


def test_extract_topology_uses_services_docker_containers() -> None:
    out = _extract_topology(
        {
            "nginx": {"version": "1.29.3", "mode": "DOCKER", "servers": []},
            "services": {
                "docker_containers": [
                    {
                        "name": "chatduel-backend",
                        "image": "chatduel/backend:latest",
                        "status": "running",
                        "ports": [{"host_port": 3000}],
                    }
                ]
            },
            "runtime": {"docker": {"containers": []}},
        }
    )

    docker_apps = [a for a in out["apps"] if a.get("type") == "docker"]
    assert len(docker_apps) == 1
    assert docker_apps[0]["name"] == "chatduel-backend"
    assert docker_apps[0]["status"] == "running"


def test_extract_topology_dedupes_docker_host_ports() -> None:
    out = _extract_topology(
        {
            "nginx": {"version": "1.29.3", "mode": "DOCKER", "servers": []},
            "services": {
                "docker_containers": [
                    {
                        "name": "chatduel-nginx",
                        "image": "nginx:alpine",
                        "status": "running",
                        "ports": [
                            {"host_port": 443},
                            {"host_port": 443},
                            {"host_port": 80},
                            {"host_port": 80},
                        ],
                    }
                ]
            },
        }
    )

    docker_apps = [a for a in out["apps"] if a.get("type") == "docker"]
    assert len(docker_apps) == 1
    assert docker_apps[0]["ports"] == [443, 80]


def test_extract_topology_dedupes_network_endpoints() -> None:
    out = _extract_topology(
        {
            "nginx": {"version": "1.29.3", "mode": "DOCKER", "servers": []},
            "network_surface": {
                "endpoints": [
                    {"address": "0.0.0.0", "port": 80, "protocol": "tcp"},
                    {"address": "0.0.0.0", "port": 80, "protocol": "tcp"},
                    {"address": "0.0.0.0", "port": 443, "protocol": "tcp"},
                ]
            },
        }
    )

    assert out["network"] == [
        {"address": "0.0.0.0", "port": 80, "protocol": "tcp"},
        {"address": "0.0.0.0", "port": 443, "protocol": "tcp"},
    ]


def test_extract_support_pack_keeps_not_accessible_status() -> None:
    pack = _extract_support_pack(
        type("Job", (), {"id": 69, "status": "success", "started_at": None, "finished_at": None, "server_host": "host"})(),
        {
            "hostname": "host",
            "doctor_version": "1.8.0",
            "commit_hash": "abc123",
            "nginx": {"mode": "DOCKER", "version": "1.29.3"},
            "os": {"name": "Ubuntu", "version": "24.04", "codename": "noble"},
            "logs": {
                "collection_status": {"journal.oom_24h": "not_accessible"},
                "collection_notes": {"journal.oom_24h": "ssh execution error: channelexception(2, 'connect failed')"},
            },
        },
        {},
    )

    row = next(item for item in pack["coverage_matrix"] if item["check"] == "journalctl OOM (24h)")
    assert row["status"] == "not_accessible"
    assert "connect failed" in row["detail"]


def test_extract_resources_falls_back_to_telemetry_memory() -> None:
    out = _extract_resources(
        {
            "telemetry": {
                "mem_total_mb": 3819,
                "mem_available_mb": 2026,
                "cpu_cores": 2,
                "load_1": 0.31,
                "load_5": 0.25,
                "load_15": 0.22,
            },
            "resources": {
                "oom_events_24h": 8,
                "collection_status": {"resources.meminfo": "not_accessible"},
                "collection_notes": {"resources.meminfo": "ssh execution error: channelexception(2, 'connect failed')"},
            },
        }
    )

    assert out["has_data"] is True
    assert out["mem_total_mb"] == 3819
    assert out["mem_available_mb"] == 2026
    assert out["mem_used_mb"] == 1793
    assert out["mem_used_percent"] == 47


def test_extract_support_pack_marks_equivalent_probe_as_collected() -> None:
    pack = _extract_support_pack(
        type("Job", (), {"id": 72, "status": "success", "started_at": None, "finished_at": None, "server_host": "host"})(),
        {
            "hostname": "host",
            "doctor_version": "1.8.0",
            "commit_hash": "abc123",
            "nginx": {"mode": "DOCKER", "version": "1.29.3"},
            "os": {"name": "Ubuntu", "version": "24.04", "codename": "noble"},
            "telemetry": {"mem_total_mb": 3819, "mem_available_mb": 2026},
            "logs": {
                "collection_status": {"journal.oom_24h": "not_accessible"},
                "collection_notes": {"journal.oom_24h": "ssh execution error: channelexception(2, 'connect failed')"},
            },
            "resources": {
                "collection_status": {
                    "resources.journal_oom": "collected",
                    "resources.meminfo": "not_accessible",
                },
                "collection_notes": {
                    "resources.meminfo": "ssh execution error: channelexception(2, 'connect failed')",
                },
            },
        },
        {},
    )

    oom_row = next(item for item in pack["coverage_matrix"] if item["check"] == "journalctl OOM (24h)")
    mem_row = next(item for item in pack["coverage_matrix"] if item["check"] == "host memory info")

    assert oom_row["status"] == "collected"
    assert "resources journal" in oom_row["detail"]
    assert mem_row["status"] == "collected"
    assert "telemetry memory" in mem_row["detail"]


def test_extract_logs_falls_back_to_resources_oom_count() -> None:
    out = _extract_logs(
        {
            "logs": {
                "journal_errors_24h": 1609,
                "journal_oom_events_24h": None,
                "collection_status": {"journal.oom_24h": "not_accessible"},
            },
            "resources": {
                "oom_events_24h": 8,
            },
        }
    )

    assert out["has_data"] is True
    assert out["journal_errors_24h"] == 1609
    assert out["journal_oom_events_24h"] == 8
