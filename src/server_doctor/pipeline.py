"""Shared scan + diagnosis pipeline.

Extracts the core logic from cli.py so both CLI and web can reuse it.
Public API:
    run_full_scan(ssh) -> ServerModel
    run_full_diagnosis(model, ssh, ...) -> DiagnosisResult
"""

import contextlib
import datetime
import json
import os
import subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

from server_doctor import __version__
from server_doctor.analyzer.app_detector import AppDetector
from server_doctor.analyzer.correlation_engine import CorrelationEngine
from server_doctor.analyzer.server_doctor import ServerDoctorAnalyzer
from server_doctor.analyzer.server_auditor import ServerAuditor
from server_doctor.connector.ssh import SSHConnector
from server_doctor.engine.deduplication import deduplicate_findings
from server_doctor.engine.scoring import ScoringEngine
from server_doctor.model.finding import Finding
from server_doctor.model.server import ServerModel
from server_doctor.parser.nginx_conf import NginxConfigParser
from server_doctor.scanner.certbot import CertbotScanner
from server_doctor.scanner.docker import DockerScanner
from server_doctor.scanner.filesystem import FilesystemScanner
from server_doctor.scanner.firewall import FirewallScanner
from server_doctor.scanner.kernel_limits import KernelLimitsScanner
from server_doctor.scanner.logs import LogsScanner
from server_doctor.scanner.mysql import MySQLScanner
from server_doctor.scanner.network_surface import NetworkSurfaceScanner
from server_doctor.scanner.nginx import NginxScanner
from server_doctor.scanner.nodejs import NodeScanner
from server_doctor.scanner.ops_posture import OpsPostureScanner
from server_doctor.scanner.php import PHPScanner
from server_doctor.scanner.redis import RedisScanner
from server_doctor.scanner.resources import ResourcesScanner
from server_doctor.scanner.security_baseline import SecurityBaselineScanner
from server_doctor.scanner.storage import StorageScanner
from server_doctor.scanner.systemd import SystemdScanner
from server_doctor.scanner.telemetry import TelemetryScanner
from server_doctor.scanner.tls_status import TLSStatusScanner
from server_doctor.scanner.upstream_probe import UpstreamProbeScanner
from server_doctor.scanner.vulnerability import VulnerabilityScanner
from server_doctor.scanner.workers import WorkerScanner


@dataclass
class DiagnosisResult:
    """Result from run_full_diagnosis()."""

    findings: list[Finding]
    score: int
    topology_snapshot: dict[str, Any]
    trend: Any = None
    ws_inventory: list[Any] = field(default_factory=list)
    suppressed_findings: list[Finding] = field(default_factory=list)
    waiver_source: str | None = None


def run_full_scan(
    ssh: SSHConnector,
    log_fn: Callable[[str], None] | None = None,
    repo_scan_paths: str | None = None,
    progress_fn: Callable[[int], None] | None = None,
) -> ServerModel:
    """Run all scanners and build the ServerModel.

    Extracted from cli.py:_scan_server(). This is the read-only scanning phase.

    Args:
        ssh: Active SSH connection.
        log_fn: Optional callback for progress logging (used by web job runner).
        repo_scan_paths: Optional comma-separated paths to scan for repos.
        progress_fn: Optional callback for progress percentage (0-40 for scan phase).

    Returns:
        Fully populated ServerModel.
    """
    def _log(msg: str) -> None:
        if log_fn:
            log_fn(msg)

    def _progress(pct: int) -> None:
        if progress_fn:
            progress_fn(pct)

    def _retry_once(label: str, fn: Callable[[], Any], current: Any) -> Any:
        """Retry a scanner once when the first result looks inconclusive."""
        _log(f"  - {label} scan looked incomplete; retrying once...")
        try:
            fresh = fn()
            return fresh if fresh is not None else current
        except Exception as e:
            _log(f"  - {label} retry failed: {e}")
            return current

    def _enum_text(value: Any) -> str:
        raw = getattr(value, "value", value)
        return str(raw).strip().lower() if raw is not None else ""

    def _env_int(name: str, default: int, minimum: int, maximum: int) -> int:
        raw = os.getenv(name, str(default)).strip()
        try:
            value = int(raw)
        except ValueError:
            value = default
        return max(minimum, min(maximum, value))

    def _ssh_parallel_hint() -> int:
        hint = getattr(ssh, "_max_parallel_commands", None)
        if isinstance(hint, int) and hint > 0:
            return hint
        return 1

    def _telemetry_has_signal(data: Any) -> bool:
        if data is None:
            return False
        has_cpu = getattr(data, "cpu_cores", None) is not None
        has_load = any(
            getattr(data, attr, None) is not None
            for attr in ("load_1", "load_5", "load_15")
        )
        has_mem = getattr(data, "mem_total_mb", None) is not None
        has_disks = bool(getattr(data, "disks", None))
        return has_cpu or has_load or has_mem or has_disks

    _log("Starting filesystem scan...")
    _progress(10)
    os_scanner = FilesystemScanner(ssh)
    from server_doctor.scanner.nginx_collector import NginxCollector
    collector = NginxCollector(ssh)
    _log("  - collecting Nginx runtime/config...")
    nginx_data = collector.collect()
    _log("  - Nginx runtime/config collection complete")

    nginx_scanner = NginxScanner(ssh)
    php_scanner = PHPScanner(ssh)

    _log("  - collecting OS release info...")
    os_info = os_scanner.get_os_info()
    _log("  - OS release collection complete")
    from server_doctor.model.server import PHPInfo
    _log("  - collecting PHP/FPM info...")
    php_data = php_scanner.scan()
    _log("  - PHP/FPM collection complete")
    php_info = PHPInfo(
        versions=php_data.versions,
        default_version=php_data.default_version,
        sockets=php_data.fpm_sockets,
        fpm_configs=php_data.pool_configs,
    )
    _progress(15)

    _log("Scanning secondary services in parallel...")
    docker_scanner = DockerScanner(ssh)
    mysql_scanner = MySQLScanner(ssh)
    node_scanner = NodeScanner(ssh)
    network_scanner = NetworkSurfaceScanner(ssh)
    firewall_scanner = FirewallScanner(ssh)
    telemetry_scanner = TelemetryScanner(ssh)
    logs_scanner = LogsScanner(ssh)
    storage_scanner = StorageScanner(ssh)
    resources_scanner = ResourcesScanner(ssh)
    kernel_limits_scanner = KernelLimitsScanner(ssh)
    baseline_scanner = SecurityBaselineScanner(ssh)
    vulnerability_scanner = VulnerabilityScanner(ssh)
    ops_posture_scanner = OpsPostureScanner(ssh)
    from server_doctor.scanner.backup_readiness import BackupReadinessScanner
    from server_doctor.scanner.dns_tls import DnsTlsScanner
    from server_doctor.scanner.http_probe import HttpProbeScanner
    from server_doctor.scanner.laravel_runtime import LaravelRuntimeScanner
    from server_doctor.scanner.mysql_deep import MySQLDeepScanner
    from server_doctor.scanner.node_runtime import NodeRuntimeScanner
    from server_doctor.scanner.php_fpm_deep import PhpFpmDeepScanner
    from server_doctor.scanner.redis_deep import RedisDeepScanner

    http_probe_scanner = HttpProbeScanner(ssh)
    php_fpm_deep_scanner = PhpFpmDeepScanner(ssh)
    laravel_runtime_scanner = LaravelRuntimeScanner(ssh)
    node_runtime_scanner = NodeRuntimeScanner(ssh)
    mysql_deep_scanner = MySQLDeepScanner(ssh)
    redis_deep_scanner = RedisDeepScanner(ssh)
    dns_tls_scanner = DnsTlsScanner(ssh)
    backup_readiness_scanner = BackupReadinessScanner(ssh)

    def scan_service(name, scanner, method="scan"):
        try:
            return (name, getattr(scanner, method)())
        except Exception as e:
            _log(f"  - {name} scan error: {e}")
            return (name, None)

    def _run_scanner_batch(
        scanners: list[tuple[str, Any, str]],
        *,
        max_workers: int,
    ) -> dict[str, Any]:
        batch_results: dict[str, Any] = {}
        if max_workers <= 1:
            for name, scanner, method in scanners:
                _log(f"  - {name} scan starting...")
                item_name, data = scan_service(name, scanner, method)
                batch_results[item_name] = data
                _log(f"  - {item_name} scan complete")
            return batch_results

        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_to_name = {
                executor.submit(scan_service, name, scanner, method): name
                for name, scanner, method in scanners
            }
            for future in as_completed(future_to_name):
                name, data = future.result()
                batch_results[name] = data
                _log(f"  - {name} scan complete")
        return batch_results

    secondary_scanners = [
        ("docker", docker_scanner, "scan"),
        ("mysql", mysql_scanner, "scan"),
        ("node", node_scanner, "scan"),
        ("network", network_scanner, "scan"),
        ("firewall", firewall_scanner, "scan_details"),
        ("telemetry", telemetry_scanner, "scan"),
        ("logs", logs_scanner, "scan"),
        ("storage", storage_scanner, "scan"),
        ("resources", resources_scanner, "scan"),
        ("kernel_limits", kernel_limits_scanner, "scan"),
        ("baseline", baseline_scanner, "scan"),
        ("vulnerability", vulnerability_scanner, "scan"),
        ("ops_posture", ops_posture_scanner, "scan"),
        ("node_runtime", node_runtime_scanner, "scan"),
        ("mysql_deep", mysql_deep_scanner, "scan"),
        ("redis_deep", redis_deep_scanner, "scan"),
        ("backup_readiness", backup_readiness_scanner, "scan"),
    ]

    ssh_parallel = _ssh_parallel_hint()
    secondary_workers = _env_int(
        "server_doctor_SCAN_SECONDARY_WORKERS",
        default=max(1, ssh_parallel),
        minimum=1,
        maximum=8,
    )
    results = _run_scanner_batch(secondary_scanners, max_workers=secondary_workers)

    docker_data = results.get("docker") or docker_scanner.scan.__annotations__.get("return", lambda: type("Data", (), {"status": "unknown", "containers": []})())()
    mysql_data = results.get("mysql") or mysql_scanner.scan.__annotations__.get("return", lambda: type("Data", (), {"status": "unknown", "config_detected": False, "bind_addresses": []})())()
    node_data = results.get("node") or node_scanner.scan.__annotations__.get("return", lambda: type("Data", (), {"status": "unknown", "processes": []})())()
    network_data = results.get("network") or network_scanner.scan.__annotations__.get("return", lambda: type("Data", (), {"listeners": []})())()
    firewall_details = results.get("firewall") or {"state": "unknown", "ufw_enabled": None, "ufw_default_incoming": None, "rules": []}
    telemetry_data = results.get("telemetry")
    if telemetry_data is None:
        from server_doctor.model.server import TelemetryModel

        telemetry_data = TelemetryModel()
    logs_data = results.get("logs")
    if logs_data is None:
        from server_doctor.model.server import LogsModel

        logs_data = LogsModel()
    storage_data = results.get("storage")
    if storage_data is None:
        from server_doctor.model.server import StorageModel

        storage_data = StorageModel()
    resources_data = results.get("resources")
    if resources_data is None:
        from server_doctor.model.server import ResourcesModel

        resources_data = ResourcesModel()
    kernel_limits_data = results.get("kernel_limits")
    if kernel_limits_data is None:
        from server_doctor.model.server import KernelLimitsModel

        kernel_limits_data = KernelLimitsModel()
    baseline_data = results.get("baseline")
    vulnerability_data = results.get("vulnerability")
    ops_posture_data = results.get("ops_posture")
    if ops_posture_data is None:
        from server_doctor.model.server import OpsPostureModel

        ops_posture_data = OpsPostureModel()
    from server_doctor.model.server import (
        BackupReadinessModel,
        DnsTlsModel,
        HttpProbeModel,
        LaravelRuntimeModel,
        MySQLDeepModel,
        NodeRuntimeModel,
        PhpFpmDeepModel,
        RedisDeepModel,
    )

    node_runtime_data = results.get("node_runtime") or NodeRuntimeModel()
    mysql_deep_data = results.get("mysql_deep") or MySQLDeepModel()
    redis_deep_data = results.get("redis_deep") or RedisDeepModel()
    backup_readiness_data = results.get("backup_readiness") or BackupReadinessModel()

    if not _telemetry_has_signal(telemetry_data):
        telemetry_data = _retry_once("telemetry", telemetry_scanner.scan, telemetry_data)

    # Consistency retries for volatile scanner outputs.
    docker_mode = str(getattr(nginx_data, "mode", "")).upper() == "DOCKER"
    docker_containers = getattr(docker_data, "containers", []) or []
    docker_status = getattr(docker_data, "status", None)
    docker_capability = _enum_text(getattr(docker_status, "capability", None))
    ops_docker_signals = any(
        bool(getattr(ops_posture_data, name, None))
        for name in (
            "docker_root_user_containers",
            "docker_no_memory_limit_containers",
            "docker_no_readonly_rootfs_containers",
            "docker_privileged_containers",
        )
    )
    if docker_mode and (not docker_containers) and (
        docker_capability in {"none", "limited", "capabilitylevel.none", "capabilitylevel.limited"}
        or ops_docker_signals
    ):
        docker_data = _retry_once("docker", docker_scanner.scan, docker_data)

    network_endpoints = getattr(network_data, "endpoints", None)
    if network_endpoints is None:
        network_endpoints = getattr(network_data, "listeners", None)
    if not network_endpoints:
        network_data = _retry_once("network", network_scanner.scan, network_data)

    if (firewall_details or {}).get("state", "unknown") == "unknown":
        firewall_details = _retry_once("firewall", firewall_scanner.scan_details, firewall_details)

    firewall_state = firewall_details.get("state", "unknown")

    _log("Preparing supply-chain (repo) path discovery...")
    _progress(22)
    from server_doctor.model.server import SupplyChainModel
    supply_chain: SupplyChainModel = SupplyChainModel(enabled=False)
    requested_repo_paths: list[str] = []
    try:
        from server_doctor.scanner.repo_ci import parse_repo_paths_from_env

        # Use provided repo_scan_paths if given, otherwise fall back to env vars.
        if repo_scan_paths:
            requested_repo_paths = [p.strip() for p in repo_scan_paths.split(",") if p.strip()]
        else:
            requested_repo_paths = parse_repo_paths_from_env()
    except Exception:
        requested_repo_paths = []

    from server_doctor.model.server import ServicesModel
    services = ServicesModel(
        docker=docker_data.status,
        docker_containers=docker_data.containers,
        mysql=mysql_data.status,
        mysql_config_detected=mysql_data.config_detected,
        mysql_bind_addresses=mysql_data.bind_addresses,
        node=node_data.status,
        node_processes=node_data.processes,
        firewall=firewall_state,
        firewall_ufw_enabled=firewall_details.get("ufw_enabled"),
        firewall_ufw_default_incoming=firewall_details.get("ufw_default_incoming"),
        firewall_rules=firewall_details.get("rules", []),
    )

    _log("Scanning runtime intelligence in parallel...")
    _progress(28)
    systemd_scanner = SystemdScanner(ssh)
    redis_scanner = RedisScanner(ssh)
    worker_scanner = WorkerScanner(ssh)

    runtime_scanners = [
        ("systemd", systemd_scanner, "scan"),
        ("redis", redis_scanner, "scan"),
        ("worker", worker_scanner, "scan"),
    ]

    runtime_workers = _env_int(
        "server_doctor_SCAN_RUNTIME_WORKERS",
        default=max(1, min(3, ssh_parallel)),
        minimum=1,
        maximum=4,
    )
    runtime_results = _run_scanner_batch(runtime_scanners, max_workers=runtime_workers)

    systemd_data = runtime_results.get("systemd") or systemd_scanner.scan.__annotations__.get("return", lambda: type("Data", (), {"status": "unknown", "services": []})())()
    redis_data = runtime_results.get("redis") or redis_scanner.scan.__annotations__.get("return", lambda: type("Data", (), {"status": "unknown", "instances": []})())()
    worker_data = runtime_results.get("worker") or worker_scanner.scan.__annotations__.get("return", lambda: type("Data", (), {"status": "unknown", "processes": [], "scheduler_detected": False, "scheduler_type": None})())()

    systemd_services = getattr(systemd_data, "services", []) or []
    systemd_state = _enum_text(getattr(getattr(systemd_data, "status", None), "state", None))
    if not systemd_services and systemd_state in {"unknown", "servicestate.unknown"}:
        systemd_data = _retry_once("systemd", systemd_scanner.scan, systemd_data)

    from server_doctor.model.server import RuntimeModel
    runtime = RuntimeModel(
        systemd=systemd_data.status,
        systemd_services=systemd_data.services,
        redis=redis_data.status,
        redis_instances=redis_data.instances,
        workers=worker_data.status,
        worker_processes=worker_data.processes,
        scheduler_detected=worker_data.scheduler_detected,
        scheduler_type=worker_data.scheduler_type,
    )

    _log("Parsing nginx configuration...")
    _progress(32)
    parser = NginxConfigParser()
    nginx_info = parser.parse(nginx_data.config_dump, version=nginx_data.version)
    nginx_info.mode = nginx_data.mode
    nginx_info.container_id = nginx_data.container_id
    nginx_info.path_mapping = nginx_data.path_mapping
    if getattr(nginx_data, "config_dump", ""):
        worker_conn_match = KernelLimitsScanner._WORKER_CONN_RE.search(nginx_data.config_dump)
        if worker_conn_match and getattr(kernel_limits_data, "nginx_worker_connections", None) is None:
            try:
                kernel_limits_data.nginx_worker_connections = int(worker_conn_match.group(1))
            except ValueError:
                pass

        proc_match = KernelLimitsScanner._WORKER_PROC_RE.search(nginx_data.config_dump)
        if proc_match and getattr(kernel_limits_data, "nginx_worker_processes", None) is None:
            token = proc_match.group(1).strip().lower()
            if token.isdigit():
                kernel_limits_data.nginx_worker_processes = int(token)
            elif token == "auto":
                cpu_cores = (
                    getattr(telemetry_data, "cpu_cores", None)
                    or getattr(resources_data, "cpu_cores", None)
                )
                if isinstance(cpu_cores, int) and cpu_cores > 0:
                    kernel_limits_data.nginx_worker_processes = cpu_cores

        if (
            getattr(kernel_limits_data, "nginx_worker_connections", None) is not None
            or getattr(kernel_limits_data, "nginx_worker_processes", None) is not None
        ):
            kernel_limits_data.collection_status["kernel.nginx_dump"] = "collected"
            kernel_limits_data.collection_notes.pop("kernel.nginx_dump", None)

    _log("Scanning TLS and certificates in parallel...")
    _progress(34)
    certbot_scanner = CertbotScanner(ssh)
    tls_scanner = TLSStatusScanner(ssh)
    probe_scanner = UpstreamProbeScanner(ssh)

    def scan_nginx_related(name, scanner, method, *args):
        try:
            return (name, getattr(scanner, method)(*args))
        except Exception as e:
            return (name, None)

    nginx_scanners = [
        ("certbot", certbot_scanner, "scan", nginx_info),
        ("tls", tls_scanner, "scan", nginx_info),
    ]

    nginx_results = {}
    nginx_workers = _env_int(
        "server_doctor_SCAN_NGINX_WORKERS",
        default=max(1, min(2, ssh_parallel)),
        minimum=1,
        maximum=3,
    )
    if nginx_workers <= 1:
        for name, scanner, method, arg in nginx_scanners:
            item_name, data = scan_nginx_related(name, scanner, method, arg)
            nginx_results[item_name] = data
            _log(f"  - {item_name} scan complete")
    else:
        with ThreadPoolExecutor(max_workers=nginx_workers) as executor:
            future_to_name = {
                executor.submit(scan_nginx_related, name, scanner, method, arg): name
                for name, scanner, method, arg in nginx_scanners
            }
            for future in as_completed(future_to_name):
                name, data = future.result()
                nginx_results[name] = data
                _log(f"  - {name} scan complete")

    certbot_data = nginx_results.get("certbot")
    tls_data = nginx_results.get("tls")
    probe_enabled = os.getenv("server_doctor_ACTIVE_PROBES", "1").strip().lower() not in {
        "0", "false", "no", "off"
    }
    upstream_probes = probe_scanner.scan(nginx_info, enabled=probe_enabled)

    # Discovery (Server-Block Centric)
    valid_roots, skipped_roots = nginx_scanner.get_all_roots(nginx_info)
    nginx_info.skipped_paths = skipped_roots

    _log("Detecting applications...")
    _progress(36)
    detector = AppDetector()
    candidate_roots: dict[str, dict] = {}

    for server in nginx_info.servers:
        roots = []
        if server.root:
            roots.append(nginx_scanner._normalize_project_path(server.root))
        else:
            for loc in server.locations:
                if loc.root:
                    roots.append(nginx_scanner._normalize_project_path(loc.root))
                if loc.alias:
                    roots.append(nginx_scanner._normalize_project_path(loc.alias))

        for root in roots:
            if nginx_scanner._is_dynamic_path(root):
                continue
            actual_host_path = nginx_info.translate_path(root)
            if actual_host_path not in candidate_roots:
                candidate_roots[actual_host_path] = {"domains": [], "source": "nginx"}
            names = server.server_names if server.server_names else ["default"]
            for name in names:
                if name not in candidate_roots[actual_host_path]["domains"]:
                    candidate_roots[actual_host_path]["domains"].append(name)

    # Discovery via Docker Bind Mounts
    for container in services.docker_containers:
        for mount in container.mounts:
            if mount.get("type") == "bind":
                host_path = mount.get("source")
                if host_path:
                    normalized_path = nginx_scanner._normalize_project_path(host_path)
                    if normalized_path not in candidate_roots:
                        candidate_roots[normalized_path] = {
                            "domains": [f"Docker: {container.name}"],
                            "source": "docker",
                        }

    # Discovery via Node Processes
    for proc in services.node_processes:
        if proc.cwd:
            host_cwd = proc.cwd
            source_label = f"Node PID: {proc.pid}"
            if proc.container_id:
                container = next(
                    (c for c in services.docker_containers
                     if c.id and c.id.startswith(proc.container_id)),
                    None,
                )
                if container:
                    host_cwd = container.translate_path(proc.cwd)
                    source_label = f"Node in Docker: {container.name}"
            normalized_cwd = nginx_scanner._normalize_project_path(host_cwd)
            if normalized_cwd not in candidate_roots:
                candidate_roots[normalized_cwd] = {
                    "domains": [source_label],
                    "source": "node",
                }

    # Scan all unique candidates in parallel
    unique_paths = sorted(candidate_roots.keys(), key=len)

    def _is_repo_candidate_path(path: str) -> bool:
        if not path or not path.startswith("/"):
            return False
        blocked_roots = {"/", "/proc", "/sys", "/dev", "/run", "/tmp", "/var/run"}
        if path in blocked_roots:
            return False
        if any(path.startswith(root + "/") for root in blocked_roots if root != "/"):
            return False
        return ssh.dir_exists(path)

    def _dedupe_paths(paths: list[str]) -> list[str]:
        unique: list[str] = []
        seen: set[str] = set()
        for raw in paths:
            path = (raw or "").strip().rstrip("/")
            if not path:
                continue
            if path not in seen:
                unique.append(path)
                seen.add(path)
        return unique

    _log("Scanning supply-chain (repo) signals...")
    effective_repo_paths = list(requested_repo_paths)
    if not effective_repo_paths:
        auto_candidates: list[str] = []
        for path in unique_paths:
            if not _is_repo_candidate_path(path):
                continue
            auto_candidates.append(path)
            if path.count("/") >= 2:
                parent = path.rsplit("/", 1)[0]
                if _is_repo_candidate_path(parent):
                    auto_candidates.append(parent)

        # Fall back to common code roots only when topology discovery found nothing.
        if not auto_candidates:
            for common_dir in ("/var/www", "/srv", "/opt", "/home"):
                if ssh.dir_exists(common_dir):
                    auto_candidates.append(common_dir)

        effective_repo_paths = _dedupe_paths(auto_candidates)

    try:
        from server_doctor.scanner.repo_ci import RepoCIScanner

        if effective_repo_paths:
            if requested_repo_paths:
                _log(f"  - Using provided repo path(s): {', '.join(effective_repo_paths[:5])}")
            else:
                _log(
                    "  - Auto-discovered repo path(s): "
                    + ", ".join(effective_repo_paths[:5])
                    + (" ..." if len(effective_repo_paths) > 5 else "")
                )
            supply_chain = RepoCIScanner(ssh, log_fn=_log).scan(effective_repo_paths)
            if not requested_repo_paths:
                supply_chain.notes.append(
                    "Repo paths were auto-discovered from nginx roots, docker mounts, node process cwd, and common code directories."
                )
        else:
            _log("  - No explicit or auto-discovered repo paths found; skipping supply-chain scan.")
    except Exception as e:
        _log(f"  - Supply-chain scan failed: {e}")
        supply_chain = SupplyChainModel(enabled=False)

    _progress(37)

    projects: list = []

    def scan_project(site_path: str) -> Any | None:
        """Scan a single project directory."""
        if not ssh.dir_exists(site_path):
            return None

        scan_data = os_scanner.scan_directory(site_path)
        basename = site_path.split("/")[-1].lower()
        asset_folders = {"assets", "images", "img", "css", "js", "storage", "build", "fonts"}

        composer_content = ssh.read_file(f"{site_path}/composer.json")
        composer_json = None
        if composer_content:
            try:
                composer_json = json.loads(composer_content)
            except Exception:
                pass

        package_content = ssh.read_file(f"{site_path}/package.json")
        package_json = None
        if package_content:
            try:
                package_json = json.loads(package_content)
            except Exception:
                pass

        detection = detector.detect(
            scan_data,
            composer_json=composer_json,
            package_json=package_json,
            docker_containers=services.docker_containers,
        )

        if basename in asset_folders and detection.confidence < 0.5:
            return None

        project_info = detector.to_project_info(scan_data, detection)
        project_info.discovery_source = candidate_roots[site_path]["source"]

        # Socket Mapping
        from server_doctor.actions.report import ReportAction
        from rich.console import Console as _RichConsole
        _dummy_console = _RichConsole(quiet=True)
        reporter_dummy = ReportAction(_dummy_console)
        project_info.php_socket = reporter_dummy._find_php_socket_for_project(
            ServerModel(hostname="", nginx=nginx_info),
            project_info.path,
        )

        return project_info

    _log(f"Scanning {len(unique_paths)} project candidates in parallel...")
    project_workers = _env_int(
        "server_doctor_SCAN_PROJECT_WORKERS",
        default=max(1, ssh_parallel),
        minimum=1,
        maximum=8,
    )
    if unique_paths:
        project_workers = min(project_workers, len(unique_paths))
    if max(1, project_workers) <= 1:
        completed = 0
        for path in unique_paths:
            try:
                project_info = scan_project(path)
                if project_info:
                    projects.append(project_info)
                completed += 1
                if completed % 5 == 0 or completed == len(unique_paths):
                    _log(f"  - Scanned {completed}/{len(unique_paths)} projects...")
                    _progress(36 + int((completed / len(unique_paths)) * 3))
            except Exception as e:
                _log(f"  - Failed to scan {path}: {e}")
    else:
        with ThreadPoolExecutor(max_workers=max(1, project_workers)) as executor:
            future_to_path = {executor.submit(scan_project, path): path for path in unique_paths}
            completed = 0
            for future in as_completed(future_to_path):
                path = future_to_path[future]
                try:
                    project_info = future.result()
                    if project_info:
                        projects.append(project_info)
                    completed += 1
                    if completed % 5 == 0 or completed == len(unique_paths):
                        _log(f"  - Scanned {completed}/{len(unique_paths)} projects...")
                        # Update progress from 36% to 39% based on completion
                        _progress(36 + int((completed / len(unique_paths)) * 3))
                except Exception as e:
                    _log(f"  - Failed to scan {path}: {e}")
    _progress(40)

    # Get local git hash
    commit_hash = "unknown"
    try:
        commit_hash = subprocess.check_output(
            ["git", "rev-parse", "--short", "HEAD"],
            stderr=subprocess.DEVNULL,
            cwd=Path(__file__).parent.parent,
        ).decode().strip()
    except Exception:
        pass

    try:
        http_probe_data = http_probe_scanner.scan(nginx_info)
    except Exception as e:
        _log(f"  - http probe scan error: {e}")
        http_probe_data = HttpProbeModel(enabled=False, notes=[str(e)])

    try:
        php_fpm_deep_data = php_fpm_deep_scanner.scan(php_info.sockets)
    except Exception as e:
        _log(f"  - php-fpm deep scan error: {e}")
        php_fpm_deep_data = PhpFpmDeepModel(enabled=False, notes=[str(e)])

    try:
        laravel_runtime_data = laravel_runtime_scanner.scan(projects)
    except Exception as e:
        _log(f"  - laravel runtime scan error: {e}")
        laravel_runtime_data = LaravelRuntimeModel(enabled=False, notes=[str(e)])

    try:
        dns_tls_data = dns_tls_scanner.scan(nginx_info)
    except Exception as e:
        _log(f"  - dns/tls scan error: {e}")
        dns_tls_data = DnsTlsModel(enabled=False, notes=[str(e)])

    model = ServerModel(
        hostname=ssh.config.host,
        os=os_info,
        nginx=nginx_info,
        nginx_status=nginx_data.status,
        php=php_info,
        services=services,
        projects=projects,
        telemetry=telemetry_data,
        logs=logs_data,
        storage=storage_data,
        resources=resources_data,
        kernel_limits=kernel_limits_data,
        security_baseline=baseline_data,
        ops_posture=ops_posture_data,
        vulnerability=vulnerability_data,
        certbot=certbot_data,
        tls=tls_data,
        network_surface=network_data,
        upstream_probes=upstream_probes,
        supply_chain=supply_chain,
        http_probes=http_probe_data,
        php_fpm_deep=php_fpm_deep_data,
        laravel_runtime=laravel_runtime_data,
        node_runtime=node_runtime_data,
        mysql_deep=mysql_deep_data,
        redis_deep=redis_deep_data,
        dns_tls=dns_tls_data,
        backup_readiness=backup_readiness_data,
        scan_timestamp=datetime.datetime.now().isoformat(),
        doctor_version=__version__,
        commit_hash=commit_hash,
        runtime=runtime,
    )

    # Correlation
    correlator = CorrelationEngine(model)
    correlator.correlate_all()

    _log("Scan complete.")
    return model


def run_full_diagnosis(
    model: ServerModel,
    ssh: SSHConnector,
    *,
    enable_history: bool = True,
    waiver_file: Path | None = None,
    minimal: bool = False,
    laravel: bool = True,
    ports: bool = True,
    security: bool = True,
    phpfpm: bool = True,
    performance: bool = True,
    log_fn: Callable[[str], None] | None = None,
    devops_enabled: bool = True,
    repo_scan_paths: str | None = None,
    progress_fn: Callable[[int], None] | None = None,
) -> DiagnosisResult:
    """Run all analyzers/checks and produce scored findings.

    Extracted from cli.py:diagnose(). This is the analysis + scoring phase.

    Args:
        model: ServerModel from run_full_scan().
        ssh: Active SSH connection(needed by modular checks).
        enable_history: Track scan trends across runs.
        waiver_file: Optional YAML waiver file path.
        minimal: If True, only run baseline analyzers.
        laravel/ports/security/phpfpm/performance: Enable/disable specific checks.
        log_fn: Optional callback for progress logging.
        progress_fn: Optional callback for progress percentage (40-70 for diagnosis phase).

    Returns:
        DiagnosisResult with findings, score, topology, trend, etc.
    """
    def _log(msg: str) -> None:
        if log_fn:
            log_fn(msg)

    def _progress(pct: int) -> None:
        if progress_fn:
            progress_fn(pct)

    _log("Running analyzers in parallel...")
    _progress(40)
    dr_analyzer = ServerDoctorAnalyzer(model)

    from server_doctor.analyzer.wss_auditor import WSSAuditor
    from server_doctor.analyzer.docker_auditor import DockerAuditor
    from server_doctor.analyzer.node_auditor import NodeAuditor
    from server_doctor.analyzer.systemd_auditor import SystemdAuditor
    from server_doctor.analyzer.redis_auditor import RedisAuditor
    from server_doctor.analyzer.worker_auditor import WorkerAuditor
    from server_doctor.analyzer.mysql_auditor import MySQLAuditor
    from server_doctor.analyzer.firewall_auditor import FirewallAuditor
    from server_doctor.analyzer.kernel_limits_auditor import KernelLimitsAuditor
    from server_doctor.analyzer.logs_auditor import LogsAuditor
    from server_doctor.analyzer.telemetry_auditor import TelemetryAuditor
    from server_doctor.analyzer.security_baseline_auditor import SecurityBaselineAuditor
    from server_doctor.analyzer.resources_auditor import ResourcesAuditor
    from server_doctor.analyzer.storage_auditor import StorageAuditor
    from server_doctor.analyzer.vulnerability_auditor import VulnerabilityAuditor
    from server_doctor.analyzer.network_surface_auditor import NetworkSurfaceAuditor
    from server_doctor.analyzer.path_conflict_auditor import PathConflictAuditor
    from server_doctor.analyzer.runtime_drift_auditor import RuntimeDriftAuditor
    from server_doctor.analyzer.certbot_auditor import CertbotAuditor
    from server_doctor.analyzer.ops_posture_auditor import OpsPostureAuditor
    from server_doctor.analyzer.backup_readiness_auditor import BackupReadinessAuditor
    from server_doctor.analyzer.dns_tls_auditor import DnsTlsAuditor
    from server_doctor.analyzer.http_probe_auditor import HttpProbeAuditor
    from server_doctor.analyzer.laravel_runtime_auditor import LaravelRuntimeAuditor
    from server_doctor.analyzer.mysql_deep_auditor import MySQLDeepAuditor
    from server_doctor.analyzer.nginx_deep_auditor import NginxDeepAuditor
    from server_doctor.analyzer.node_runtime_auditor import NodeRuntimeAuditor
    from server_doctor.analyzer.php_fpm_deep_auditor import PhpFpmDeepAuditor
    from server_doctor.analyzer.redis_deep_auditor import RedisDeepAuditor
    from server_doctor.analyzer.security_headers_auditor import SecurityHeadersAuditor
    from server_doctor.analyzer.cors_auditor import CorsAuditor
    from server_doctor.analyzer.api_surface_auditor import ApiSurfaceAuditor
    from server_doctor.analyzer.host_security_auditor import HostSecurityAuditor

    wss_auditor = WSSAuditor(model)

    def _safe_audit(label: str, fn: Callable) -> list:
        try:
            return fn()
        except Exception:
            return []

    # Run all auditors in parallel
    auditors = [
        ("Server", lambda: ServerAuditor(model).audit()),
        ("WSS", wss_auditor.audit),
        ("Docker", lambda: DockerAuditor(model).audit()),
        ("Node", lambda: NodeAuditor(model).audit()),
        ("Systemd", lambda: SystemdAuditor(model).audit()),
        ("Redis", lambda: RedisAuditor(model).audit()),
        ("Worker", lambda: WorkerAuditor(model).audit()),
        ("MySQL", lambda: MySQLAuditor(model).audit()),
        ("Firewall", lambda: FirewallAuditor(model).audit()),
        ("Telemetry", lambda: TelemetryAuditor(model).audit()),
        ("Logs", lambda: LogsAuditor(model).audit()),
        ("Storage", lambda: StorageAuditor(model).audit()),
        ("Resources", lambda: ResourcesAuditor(model).audit()),
        ("KernelLimits", lambda: KernelLimitsAuditor(model).audit()),
        ("SecurityBaseline", lambda: SecurityBaselineAuditor(model).audit()),
        ("Vulnerability", lambda: VulnerabilityAuditor(model).audit()),
        ("NetworkSurface", lambda: NetworkSurfaceAuditor(model).audit()),
        ("PathConflict", lambda: PathConflictAuditor(model).audit()),
        ("RuntimeDrift", lambda: RuntimeDriftAuditor(model).audit()),
        ("Certbot", lambda: CertbotAuditor(model).audit()),
        ("OpsPosture", lambda: OpsPostureAuditor(model).audit()),
        ("HttpProbe", lambda: HttpProbeAuditor(model).audit()),
        ("NginxDeep", lambda: NginxDeepAuditor(model).audit()),
        ("PhpFpmDeep", lambda: PhpFpmDeepAuditor(model).audit()),
        ("LaravelRuntime", lambda: LaravelRuntimeAuditor(model).audit()),
        ("NodeRuntime", lambda: NodeRuntimeAuditor(model).audit()),
        ("MySQLDeep", lambda: MySQLDeepAuditor(model).audit()),
        ("RedisDeep", lambda: RedisDeepAuditor(model).audit()),
        ("DnsTls", lambda: DnsTlsAuditor(model).audit()),
        ("BackupReadiness", lambda: BackupReadinessAuditor(model).audit()),
        ("SecurityHeaders", lambda: SecurityHeadersAuditor(model).audit()),
        ("CORS", lambda: CorsAuditor(model).audit()),
        ("ApiSurface", lambda: ApiSurfaceAuditor(model).audit()),
        ("HostSecurity", lambda: HostSecurityAuditor(model).audit()),
    ]

    audit_results = []
    with ThreadPoolExecutor(max_workers=8) as executor:
        future_to_name = {executor.submit(_safe_audit, name, fn): name for name, fn in auditors}
        completed = 0
        for future in as_completed(future_to_name):
            name = future_to_name[future]
            try:
                findings = future.result()
                audit_results.extend(findings)
                completed += 1
                _log(f"  ✓ {name} analyzer complete")
                # Update progress from 40% to 65% based on completion
                _progress(40 + int((completed / len(auditors)) * 25))
            except Exception as e:
                _log(f"  ✗ {name} analyzer failed: {e}")

    legacy_findings = dr_analyzer.diagnose(additional_findings=audit_results)
    _progress(65)

    _log("Running modular checks...")
    _progress(67)
    from server_doctor.checks import CheckContext, run_checks
    import server_doctor.checks.laravel.laravel_auditor
    import server_doctor.checks.ports.port_auditor
    import server_doctor.checks.security.security_auditor
    import server_doctor.checks.phpfpm.phpfpm_auditor
    import server_doctor.checks.performance.performance_auditor
    import server_doctor.checks.devops.ci_posture_auditor
    import server_doctor.checks.devops.dependency_posture_auditor
    import server_doctor.checks.laravel.production_auditor
    import server_doctor.checks.node.node_deploy_auditor
    import server_doctor.checks.ops.backup_auditor
    import server_doctor.checks.database.database_auditor
    import server_doctor.checks.firewall.firewall_recommendation
    import server_doctor.checks.nginx.deep_config_auditor

    default_enabled = not minimal

    check_ctx = CheckContext(
        model=model,
        ssh=ssh,
        laravel_enabled=default_enabled or laravel,
        ports_enabled=default_enabled or ports,
        security_enabled=default_enabled or security,
        phpfpm_enabled=default_enabled or phpfpm,
        performance_enabled=default_enabled or performance,
        devops_enabled=True,
        node_enabled=True,
        ops_enabled=True,
        database_enabled=True,
        firewall_enabled=True,
    )

    new_findings = run_checks(check_ctx)
    findings = deduplicate_findings(legacy_findings + new_findings)
    _progress(70)

    _log("Applying waivers...")
    from server_doctor.engine.waivers import apply_waivers, default_waiver_path, load_waiver_rules
    actual_waiver_file = waiver_file or default_waiver_path()
    waiver_rules = load_waiver_rules(actual_waiver_file)
    findings, suppressed_findings = apply_waivers(findings, waiver_rules)
    waiver_source = str(actual_waiver_file) if waiver_rules else None

    ws_inventory = wss_auditor.get_inventory()
    from server_doctor.engine.topology import build_topology_snapshot
    topology_snapshot = build_topology_snapshot(model, ws_inventory)

    _log("Computing scores...")
    score_total = ScoringEngine().calculate(findings).total

    # Compute trend against previous scan
    trend = None
    if enable_history:
        from server_doctor.engine.history import ScanHistoryStore
        tracker = ScanHistoryStore()
        current_ts = model.scan_timestamp or datetime.datetime.now().isoformat()
        history_host = model.hostname if isinstance(getattr(model, "hostname", None), str) else "unknown"
        trend = tracker.compute_trend(
            history_host,
            findings,
            score_total,
            current_ts,
            current_topology=topology_snapshot,
        )
        tracker.append_scan(
            history_host,
            findings,
            score_total,
            current_ts,
            topology=topology_snapshot,
        )

    _log("Diagnosis complete.")
    return DiagnosisResult(
        findings=findings,
        score=score_total,
        topology_snapshot=topology_snapshot,
        trend=trend,
        ws_inventory=ws_inventory,
        suppressed_findings=suppressed_findings,
        waiver_source=waiver_source,
    )
