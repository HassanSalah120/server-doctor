"""
Click-based CLI for server-doctor.

IMPORTANT: This module only ORCHESTRATES. It never reasons or makes decisions.
- Loads server profiles
- Invokes engine
- Passes flags
- Formats output
"""

import contextlib
import json
import os
import re
import sys
from pathlib import Path
from typing import TYPE_CHECKING

import click
from rich.console import Console
from rich.panel import Panel

import datetime
import subprocess
from server_doctor import __version__
from server_doctor.actions.apply import ApplyAction
from server_doctor.actions.generate import GenerateAction
from server_doctor.actions.report import ReportAction
from server_doctor.actions.html_report import HTMLReportAction
from server_doctor.actions.report_bundle import ReportBundleAction
from server_doctor.analyzer.app_detector import AppDetector
from server_doctor.analyzer.server_doctor import ServerDoctorAnalyzer
from server_doctor.analyzer.server_auditor import ServerAuditor

if TYPE_CHECKING:
    from server_doctor.model.server import ProjectInfo
from server_doctor.config import ConfigManager
from server_doctor.connector.ssh import SSHConfig, SSHConnector
from server_doctor.engine.decision import DecisionEngine
from server_doctor.model.server import ProjectType, ServerModel
from server_doctor.parser.nginx_conf import NginxConfigParser
from server_doctor.scanner.filesystem import FilesystemScanner
from server_doctor.scanner.nginx import NginxScanner
from server_doctor.scanner.php import PHPScanner
from server_doctor.scanner.docker import DockerScanner
from server_doctor.scanner.mysql import MySQLScanner
from server_doctor.scanner.nodejs import NodeScanner
from server_doctor.scanner.certbot import CertbotScanner
from server_doctor.scanner.network_surface import NetworkSurfaceScanner
from server_doctor.scanner.firewall import FirewallScanner
from server_doctor.scanner.systemd import SystemdScanner
from server_doctor.scanner.redis import RedisScanner
from server_doctor.scanner.security_baseline import SecurityBaselineScanner
from server_doctor.scanner.telemetry import TelemetryScanner
from server_doctor.scanner.vulnerability import VulnerabilityScanner
from server_doctor.scanner.workers import WorkerScanner
from server_doctor.scanner.tls_status import TLSStatusScanner
from server_doctor.scanner.upstream_probe import UpstreamProbeScanner
from server_doctor.analyzer.correlation_engine import CorrelationEngine
from server_doctor.actions.safe_fix import SafeFixAction

console = Console()


def _safe_name(value: str) -> str:
    """Convert host/profile names into filesystem-safe path parts."""
    cleaned = re.sub(r"[^a-zA-Z0-9_.-]+", "-", value.strip())
    return cleaned.strip("-") or "unknown-host"


def _scan_time_label(scan_timestamp: str | None) -> str:
    """Create date-only label for output paths (dd-mm-yyyy)."""
    if scan_timestamp:
        with contextlib.suppress(ValueError):
            dt = datetime.datetime.fromisoformat(scan_timestamp.replace("Z", "+00:00"))
            return dt.strftime("%d-%m-%Y")
    return datetime.datetime.now().strftime("%d-%m-%Y")


def _resolve_html_output_path(
    output: str | None,
    hostname: str,
    scan_timestamp: str | None,
) -> Path:
    """Resolve output path for HTML report, defaulting to date-based host bundle."""
    ts_label = _scan_time_label(scan_timestamp)
    host_label = _safe_name(hostname)

    if output:
        out = Path(output).expanduser()
        # If no suffix is provided, treat as directory target.
        if out.suffix.lower() != ".html":
            return out / f"{host_label}-{ts_label}.html"
        return out

    return Path("reports") / host_label / ts_label / "report.html"


@click.group()
@click.version_option(version=__version__, prog_name="server-doctor")
@click.option("--config", "-c", type=click.Path(), help="Path to config directory")
@click.pass_context
def main(ctx: click.Context, config: str | None) -> None:
    """🩺 server-doctor: SSH-based Server Intelligence System.

    Diagnose Nginx + PHP problems, audit server health, and generate configs.
    """
    ctx.ensure_object(dict)
    config_dir = Path(config) if config else None
    ctx.obj["config_mgr"] = ConfigManager(config_dir)


def _resolve_config(ctx: click.Context, server: str) -> SSHConfig:
    """Resolve server string to SSHConfig (profile name or IP)."""
    config_mgr = ctx.obj["config_mgr"]
    cfg = config_mgr.get_profile(server)
    if cfg:
        return cfg
    
    # Otherwise treat as hostname/IP with default root user
    return SSHConfig(host=server, user="root")


def _scan_server(ctx: click.Context, ssh: SSHConnector) -> ServerModel:
    """Internal helper to run all scanners and build model."""
    with console.status("[bold blue]🔍 Scanning server...[/]"):
        os_scanner = FilesystemScanner(ssh)
        from server_doctor.scanner.nginx_collector import NginxCollector
        collector = NginxCollector(ssh)
        nginx_data = collector.collect()
        
        nginx_scanner = NginxScanner(ssh) # Keep for path normalization and sites listing
        php_scanner = PHPScanner(ssh)
        
        os_info = os_scanner.get_os_info()
        from server_doctor.model.server import PHPInfo
        php_data = php_scanner.scan()
        php_info = PHPInfo(
            versions=php_data.versions,
            default_version=php_data.default_version,
            sockets=php_data.fpm_sockets,
            fpm_configs=php_data.pool_configs,
        )

        # Phase 14: Secondary Services
        docker_scanner = DockerScanner(ssh)
        mysql_scanner = MySQLScanner(ssh)
        node_scanner = NodeScanner(ssh)
        network_scanner = NetworkSurfaceScanner(ssh)
        firewall_scanner = FirewallScanner(ssh)
        telemetry_scanner = TelemetryScanner(ssh)
        baseline_scanner = SecurityBaselineScanner(ssh)
        vulnerability_scanner = VulnerabilityScanner(ssh)

        docker_data = docker_scanner.scan()
        mysql_data = mysql_scanner.scan()
        node_data = node_scanner.scan()
        network_data = network_scanner.scan()
        firewall_details = firewall_scanner.scan_details()
        firewall_state = firewall_details.get("state", "unknown")
        telemetry_data = telemetry_scanner.scan()
        baseline_data = baseline_scanner.scan()
        vulnerability_data = vulnerability_scanner.scan()

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

        # Phase 15: Runtime Intelligence
        systemd_scanner = SystemdScanner(ssh)
        redis_scanner = RedisScanner(ssh)
        worker_scanner = WorkerScanner(ssh)

        systemd_data = systemd_scanner.scan()
        redis_data = redis_scanner.scan()
        worker_data = worker_scanner.scan()

        from server_doctor.model.server import RuntimeModel
        runtime = RuntimeModel(
            systemd=systemd_data.status,
            systemd_services=systemd_data.services,
            redis=redis_data.status,
            redis_instances=redis_data.instances,
            workers=worker_data.status,
            worker_processes=worker_data.processes,
            scheduler_detected=worker_data.scheduler_detected,
            scheduler_type=worker_data.scheduler_type
        )
        
        # Parse nginx config
        parser = NginxConfigParser()
        nginx_info = parser.parse(nginx_data.config_dump, version=nginx_data.version)
        nginx_info.mode = nginx_data.mode
        nginx_info.container_id = nginx_data.container_id
        nginx_info.path_mapping = nginx_data.path_mapping
        certbot_scanner = CertbotScanner(ssh)
        tls_scanner = TLSStatusScanner(ssh)
        probe_scanner = UpstreamProbeScanner(ssh)
        certbot_data = certbot_scanner.scan(nginx_info)
        tls_data = tls_scanner.scan(nginx_info)
        probe_enabled = os.getenv("server_doctor_ACTIVE_PROBES", "1").strip().lower() not in {"0", "false", "no", "off"}
        upstream_probes = probe_scanner.scan(nginx_info, enabled=probe_enabled)
        
        # PHASE 2: Discovery (Server-Block Centric)
        valid_roots, skipped_roots = nginx_scanner.get_all_roots(nginx_info)
        nginx_info.skipped_paths = skipped_roots
        
        # App detection
        detector = AppDetector()
        projects = []
        
        # 1. Collect roots grouped by server block to ensure domain association
        # host_path -> {"names": [domains], "source": "nginx"|"docker"|"node"}
        candidate_roots: dict[str, dict] = {} 

        for server in nginx_info.servers:
            # Prefer server root
            roots = []
            if server.root:
                roots.append(nginx_scanner._normalize_project_path(server.root))
            else:
                # Fallback to location roots if no server root exists
                for loc in server.locations:
                    if loc.root:
                        roots.append(nginx_scanner._normalize_project_path(loc.root))
                    if loc.alias:
                        roots.append(nginx_scanner._normalize_project_path(loc.alias))
            
            for root in roots:
                if nginx_scanner._is_dynamic_path(root): continue
                actual_host_path = nginx_info.translate_path(root)
                
                if actual_host_path not in candidate_roots:
                    candidate_roots[actual_host_path] = {"domains": [], "source": "nginx"}
                names = server.server_names if server.server_names else ["default"]
                for name in names:
                    if name not in candidate_roots[actual_host_path]["domains"]:
                        candidate_roots[actual_host_path]["domains"].append(name)

        # 1.1 Discovery via Docker Bind Mounts (critical for pure proxy setups)
        for container in services.docker_containers:
            for mount in container.mounts:
                if mount.get("type") == "bind":
                    host_path = mount.get("source")
                    if host_path:
                        normalized_path = nginx_scanner._normalize_project_path(host_path)
                        if normalized_path not in candidate_roots:
                            # Associate with container name
                            candidate_roots[normalized_path] = {"domains": [f"Docker: {container.name}"], "source": "docker"}

        # 1.2 Discovery via Node Processes (with Docker path translation)
        for proc in services.node_processes:
            if proc.cwd:
                host_cwd = proc.cwd
                source_label = f"Node PID: {proc.pid}"
                
                if proc.container_id:
                    # Resolve container to translate path
                    container = next((c for c in services.docker_containers if c.id and c.id.startswith(proc.container_id)), None)
                    if container:
                        host_cwd = container.translate_path(proc.cwd)
                        source_label = f"Node in Docker: {container.name}"
                
                normalized_cwd = nginx_scanner._normalize_project_path(host_cwd)
                if normalized_cwd not in candidate_roots:
                    candidate_roots[normalized_cwd] = {"domains": [source_label], "source": "node"}
        
        # 1.3 Scan all unique candidates
        unique_paths = sorted(candidate_roots.keys(), key=len)
        projects: list[ProjectInfo] = []
        
        for site_path in unique_paths:
            if not ssh.dir_exists(site_path):
                continue
                
            scan_data = os_scanner.scan_directory(site_path)
            
            # STRICTOR FILTER: If it's a directory like 'assets', 'images', 'storage' 
            # and contains no index files or composer.json, skip it.
            basename = site_path.split("/")[-1].lower()
            asset_folders = {"assets", "images", "img", "css", "js", "storage", "build", "fonts"}
            
            # Try to read composer.json
            composer_content = ssh.read_file(f"{site_path}/composer.json")
            import json
            composer_json = None
            if composer_content:
                try:
                    composer_json = json.loads(composer_content)
                except:
                    pass
            
            # Phase 14: Node support - Load package.json
            package_content = ssh.read_file(f"{site_path}/package.json")
            package_json = None
            if package_content:
                try:
                    package_json = json.loads(package_content)
                except:
                    pass

            detection = detector.detect(
                scan_data, 
                composer_json=composer_json,
                package_json=package_json,
                docker_containers=services.docker_containers
            )
            
            # If it's a known asset folder and detection is weak, skip it
            if basename in asset_folders and detection.confidence < 0.5:
                continue
            
            project_info = detector.to_project_info(scan_data, detection)
            project_info.discovery_source = candidate_roots[site_path]["source"]
            
            # PHASE 3: Socket Mapping
            from server_doctor.actions.report import ReportAction
            reporter_dummy = ReportAction(console)
            project_info.php_socket = reporter_dummy._find_php_socket_for_project(
                ServerModel(hostname="", nginx=nginx_info), 
                project_info.path
            )
            
            projects.append(project_info)
            
        # Get local git hash
        commit_hash = "unknown"
        try:
            # We assume we are running from within the git repo or it's accessible
            # If not, it will stay 'unknown'
            commit_hash = subprocess.check_output(
                ["git", "rev-parse", "--short", "HEAD"], 
                stderr=subprocess.DEVNULL,
                cwd=Path(__file__).parent.parent.parent
            ).decode().strip()
        except:
            pass

        model = ServerModel(
            hostname=ssh.config.host,
            os=os_info,
            nginx=nginx_info,
            nginx_status=nginx_data.status,
            php=php_info,
            services=services,
            projects=projects,
            telemetry=telemetry_data,
            security_baseline=baseline_data,
            vulnerability=vulnerability_data,
            certbot=certbot_data,
            tls=tls_data,
            network_surface=network_data,
            upstream_probes=upstream_probes,
            scan_timestamp=datetime.datetime.now().isoformat(),
            doctor_version=__version__,
            commit_hash=commit_hash,
            runtime=runtime
        )

        # Phase 14: Correlation
        correlator = CorrelationEngine(model)
        correlator.correlate_all()

        return model


@main.command()
@click.argument("server")
@click.pass_context
def check(ctx: click.Context, server: str) -> None:
    """CI/CD friendly one-shot command.
    
    Runs scan, diagnose, and recommend. 
    Exits with code 1 if warnings or critical findings exist.
    """
    import sys
    from server_doctor.model.evidence import Severity
    
    cfg = _resolve_config(ctx, server)
    try:
        with SSHConnector(cfg) as ssh:
            model = _scan_server(ctx, ssh)
            
            # Run analyzers
            dr_analyzer = ServerDoctorAnalyzer(model)
            from server_doctor.analyzer.wss_auditor import WSSAuditor
            from server_doctor.analyzer.docker_auditor import DockerAuditor
            from server_doctor.analyzer.node_auditor import NodeAuditor
            from server_doctor.analyzer.systemd_auditor import SystemdAuditor
            from server_doctor.analyzer.redis_auditor import RedisAuditor
            from server_doctor.analyzer.worker_auditor import WorkerAuditor
            from server_doctor.analyzer.mysql_auditor import MySQLAuditor
            from server_doctor.analyzer.firewall_auditor import FirewallAuditor
            from server_doctor.analyzer.telemetry_auditor import TelemetryAuditor
            from server_doctor.analyzer.security_baseline_auditor import SecurityBaselineAuditor
            from server_doctor.analyzer.vulnerability_auditor import VulnerabilityAuditor
            from server_doctor.analyzer.network_surface_auditor import NetworkSurfaceAuditor
            from server_doctor.analyzer.path_conflict_auditor import PathConflictAuditor
            from server_doctor.analyzer.runtime_drift_auditor import RuntimeDriftAuditor
            from server_doctor.analyzer.certbot_auditor import CertbotAuditor
            from server_doctor.checks import CheckContext, run_checks
            from server_doctor.engine.deduplication import deduplicate_findings

            wss_auditor = WSSAuditor(model)
            def _safe_audit(label: str, fn):
                try:
                    return fn()
                except Exception as e:
                    console.print(f"[dim]Skipping {label} audit due to model shape/runtime error: {e}[/]")
                    return []
            legacy_findings = dr_analyzer.diagnose(
                additional_findings=(
                    ServerAuditor(model).audit()
                    + _safe_audit("WSS", wss_auditor.audit)
                    + _safe_audit("Docker", DockerAuditor(model).audit)
                    + _safe_audit("Node", NodeAuditor(model).audit)
                    + _safe_audit("Systemd", SystemdAuditor(model).audit)
                    + _safe_audit("Redis", RedisAuditor(model).audit)
                    + _safe_audit("Worker", WorkerAuditor(model).audit)
                    + _safe_audit("MySQL", MySQLAuditor(model).audit)
                    + _safe_audit("Firewall", FirewallAuditor(model).audit)
                    + _safe_audit("Telemetry", TelemetryAuditor(model).audit)
                    + _safe_audit("SecurityBaseline", SecurityBaselineAuditor(model).audit)
                    + _safe_audit("Vulnerability", VulnerabilityAuditor(model).audit)
                    + _safe_audit("NetworkSurface", NetworkSurfaceAuditor(model).audit)
                    + _safe_audit("PathConflict", PathConflictAuditor(model).audit)
                    + _safe_audit("RuntimeDrift", RuntimeDriftAuditor(model).audit)
                    + _safe_audit("Certbot", CertbotAuditor(model).audit)
                )
            )

            # Keep check command strict by running modular checks by default.
            import server_doctor.checks.laravel.laravel_auditor
            import server_doctor.checks.ports.port_auditor
            import server_doctor.checks.security.security_auditor
            import server_doctor.checks.phpfpm.phpfpm_auditor
            import server_doctor.checks.performance.performance_auditor
            import server_doctor.checks.devops.ci_posture_auditor
            import server_doctor.checks.devops.dependency_posture_auditor

            check_ctx = CheckContext(
                model=model,
                ssh=ssh,
                laravel_enabled=True,
                ports_enabled=True,
                security_enabled=True,
                phpfpm_enabled=True,
                performance_enabled=True,
                devops_enabled=True,
            )
            findings = deduplicate_findings(legacy_findings + run_checks(check_ctx))
            
            # Report everything
            reporter = ReportAction(console)
            reporter.report_server_summary(model, findings)
            ws_inventory = wss_auditor.get_inventory()
            if ws_inventory:
                reporter.report_wss_inventory(ws_inventory)
            reporter.report_findings(findings)
            
            engine = DecisionEngine(model, findings)
            recs = engine.recommend()
            reporter.report_recommendations(recs)
            
            # Check for severity (Critical = 2, Warning = 1, Info/None = 0)
            exit_code = 0
            for f in findings:
                if f.severity == Severity.CRITICAL:
                    exit_code = 2
                    break
                if f.severity == Severity.WARNING:
                    exit_code = max(exit_code, 1)
            
            sys.exit(exit_code)
                
    except SystemExit as e:
        sys.exit(e.code)
    except Exception as e:
        console.print(f"[bold red]Error:[/] {e}")
        sys.exit(1)


@main.command()
@click.argument("server")
@click.option("--json", "output_format", flag_value="json", help="Output as JSON")
@click.option("--yaml", "output_format", flag_value="yaml", help="Output as YAML")
@click.pass_context
def scan(ctx: click.Context, server: str, output_format: str | None) -> None:
    """Scan a server and build the internal model.

    This is read-only and makes no changes to the server.
    """
    cfg = _resolve_config(ctx, server)
    try:
        with SSHConnector(cfg) as ssh:
            model = _scan_server(ctx, ssh)
            reporter = ReportAction(console)
            
            if output_format:
                reporter.export_server_model(model, output_format)
            else:
                reporter.report_server_summary(model)
    except Exception as e:
        console.print(f"[bold red]Error:[/] {e}")


@main.command()
@click.argument("server")
@click.option("--format", "fmt", type=click.Choice(["rich", "plain", "json", "html"]), default=None, help="Output format")
@click.option(
    "--output",
    "-o",
    default=None,
    help="Output file/directory for HTML report (default: reports/<host>/<dd-mm-yyyy>/report.html)",
)
@click.option("--waivers", type=click.Path(), default=None, help="YAML waiver file for accepted risks")
@click.option("--history/--no-history", "enable_history", default=True, help="Track scan trends across runs")
@click.option("--export-fix-pack", type=click.Path(), default=None, help="Export hardening.sh and nginx_patch.conf")
@click.option("--minimal", is_flag=True, help="Run baseline analyzers only (disable optional modular checks)")
@click.option("--laravel", is_flag=True, help="Enable Laravel readiness scanning (useful with --minimal)")
@click.option("--ports", is_flag=True, help="Enable port usage analyzer (useful with --minimal)")
@click.option("--security", is_flag=True, help="Enable security headers checks (useful with --minimal)")
@click.option("--phpfpm", is_flag=True, help="Enable PHP-FPM analysis (useful with --minimal)")
@click.option("--performance", is_flag=True, help="Enable performance audit (useful with --minimal)")
@click.option("--all", "run_all", is_flag=True, help="Run all optional analyzers")
@click.option("--score", is_flag=True, help="Show 0-100 summary scores")
@click.option("--explain", is_flag=True, help="Show 'why this matters' for findings")
@click.option("--fix", is_flag=True, help="Apply fixes (interactive)")
@click.option("--safe-fix", is_flag=True, help="Apply safe fixes only")
@click.option("--dry-run", is_flag=True, help="Simulate fixes without changes")
@click.option("--yes", is_flag=True, help="Skip confirmation prompts")
@click.pass_context
def diagnose(
    ctx: click.Context, 
    server: str, 
    fmt: str | None, 
    output: str | None,
    waivers: str | None,
    enable_history: bool,
    export_fix_pack: str | None,
    minimal: bool,
    laravel: bool,
    ports: bool,
    security: bool,
    phpfpm: bool,
    performance: bool,
    run_all: bool,
    score: bool,
    explain: bool,
    fix: bool,
    safe_fix: bool,
    dry_run: bool,
    yes: bool
) -> None:
    """Run full diagnosis on a server.

    Identifies misconfigurations with evidence-based findings.
    """
    import sys
    cfg = _resolve_config(ctx, server)
    
    # Default to HTML reports unless terminal/interactivity-focused flags are requested.
    if fmt is None:
        if score or explain or fix or safe_fix:
            fmt = "plain" if not sys.stdout.isatty() else "rich"
        else:
            fmt = "html"

    try:
        with SSHConnector(cfg) as ssh:
            with console.status(f"🔍 Scanning server...", spinner="dots") if fmt == "rich" else contextlib.nullcontext():
                model = _scan_server(ctx, ssh)
            
            # Run analyzers
            dr_analyzer = ServerDoctorAnalyzer(model)
            from server_doctor.analyzer.wss_auditor import WSSAuditor
            from server_doctor.analyzer.docker_auditor import DockerAuditor
            from server_doctor.analyzer.node_auditor import NodeAuditor
            from server_doctor.analyzer.systemd_auditor import SystemdAuditor
            from server_doctor.analyzer.redis_auditor import RedisAuditor
            from server_doctor.analyzer.worker_auditor import WorkerAuditor
            from server_doctor.analyzer.mysql_auditor import MySQLAuditor
            from server_doctor.analyzer.firewall_auditor import FirewallAuditor
            from server_doctor.analyzer.telemetry_auditor import TelemetryAuditor
            from server_doctor.analyzer.security_baseline_auditor import SecurityBaselineAuditor
            from server_doctor.analyzer.vulnerability_auditor import VulnerabilityAuditor
            from server_doctor.analyzer.network_surface_auditor import NetworkSurfaceAuditor
            from server_doctor.analyzer.path_conflict_auditor import PathConflictAuditor
            from server_doctor.analyzer.runtime_drift_auditor import RuntimeDriftAuditor
            from server_doctor.analyzer.certbot_auditor import CertbotAuditor

            wss_auditor = WSSAuditor(model)
            def _safe_audit(label: str, fn):
                try:
                    return fn()
                except Exception as e:
                    console.print(f"[dim]Skipping {label} audit due to model shape/runtime error: {e}[/]")
                    return []
            legacy_findings = dr_analyzer.diagnose(
                additional_findings=(
                    ServerAuditor(model).audit()
                    + _safe_audit("WSS", wss_auditor.audit)
                    + _safe_audit("Docker", DockerAuditor(model).audit)
                    + _safe_audit("Node", NodeAuditor(model).audit)
                    + _safe_audit("Systemd", SystemdAuditor(model).audit)
                    + _safe_audit("Redis", RedisAuditor(model).audit)
                    + _safe_audit("Worker", WorkerAuditor(model).audit)
                    + _safe_audit("MySQL", MySQLAuditor(model).audit)
                    + _safe_audit("Firewall", FirewallAuditor(model).audit)
                    + _safe_audit("Telemetry", TelemetryAuditor(model).audit)
                    + _safe_audit("SecurityBaseline", SecurityBaselineAuditor(model).audit)
                    + _safe_audit("Vulnerability", VulnerabilityAuditor(model).audit)
                    + _safe_audit("NetworkSurface", NetworkSurfaceAuditor(model).audit)
                    + _safe_audit("PathConflict", PathConflictAuditor(model).audit)
                    + _safe_audit("RuntimeDrift", RuntimeDriftAuditor(model).audit)
                    + _safe_audit("Certbot", CertbotAuditor(model).audit)
                )
            )
            
            # Run new modular checks
            from server_doctor.checks import CheckContext, run_checks
            import server_doctor.checks.laravel.laravel_auditor
            import server_doctor.checks.ports.port_auditor
            import server_doctor.checks.security.security_auditor
            import server_doctor.checks.phpfpm.phpfpm_auditor
            import server_doctor.checks.performance.performance_auditor
            import server_doctor.checks.devops.ci_posture_auditor
            import server_doctor.checks.devops.dependency_posture_auditor

            default_modular_checks_enabled = not minimal
            
            check_ctx = CheckContext(
                model=model,
                ssh=ssh,
                laravel_enabled=default_modular_checks_enabled or laravel or run_all,
                ports_enabled=default_modular_checks_enabled or ports or run_all,
                security_enabled=default_modular_checks_enabled or security or run_all,
                phpfpm_enabled=default_modular_checks_enabled or phpfpm or run_all,
                performance_enabled=default_modular_checks_enabled or performance or run_all,
                devops_enabled=True,
            )
            
            new_findings = run_checks(check_ctx)
            
            # Combine and perform FINAL global deduplication
            from server_doctor.engine.deduplication import deduplicate_findings
            findings = deduplicate_findings(legacy_findings + new_findings)
            # print(f"DEBUG_CLI: findings length: {len(findings)}")

            # Apply waiver/suppression rules (accepted risks)
            from server_doctor.engine.waivers import apply_waivers, default_waiver_path, load_waiver_rules
            waiver_file = Path(waivers).expanduser() if waivers else default_waiver_path()
            waiver_rules = load_waiver_rules(waiver_file)
            findings, suppressed_findings = apply_waivers(findings, waiver_rules)
            waiver_source = str(waiver_file) if waiver_rules else None
            if suppressed_findings and fmt != "json":
                console.print(
                    f"[cyan]i Suppressed {len(suppressed_findings)} waived finding(s)"
                    f"{f' from {waiver_source}' if waiver_source else ''}.[/]"
                )

            ws_inventory = wss_auditor.get_inventory()
            from server_doctor.engine.topology import build_topology_snapshot
            topology_snapshot = build_topology_snapshot(model, ws_inventory)

            # Compute trend diff against previous scan and persist history.
            trend = None
            if enable_history:
                from server_doctor.engine.history import ScanHistoryStore
                from server_doctor.engine.scoring import ScoringEngine

                tracker = ScanHistoryStore()
                current_ts = model.scan_timestamp or datetime.datetime.now().isoformat()
                score_total = ScoringEngine().calculate(findings).total
                history_host = model.hostname if isinstance(getattr(model, "hostname", None), str) else server
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

            # Optionally export generated fix-pack artifacts.
            if export_fix_pack:
                from server_doctor.actions.fix_pack import FixPackAction

                fix_pack = FixPackAction().generate(findings, export_fix_pack)
                console.print(f"[bold green]Fix pack exported:[/] {fix_pack['script']}")
                console.print(f"[bold green]Nginx patch exported:[/] {fix_pack['patch']}")

            if fmt == "html":
                html_reporter = HTMLReportAction()
                html_output_path = _resolve_html_output_path(
                    output=output,
                    hostname=model.hostname or server,
                    scan_timestamp=model.scan_timestamp,
                )
                html_output_path.parent.mkdir(parents=True, exist_ok=True)
                report_path = html_reporter.generate(
                    model,
                    findings,
                    output_path=str(html_output_path),
                    ws_inventory=ws_inventory,
                    trend=trend,
                    suppressed_findings=suppressed_findings,
                    waiver_source=waiver_source,
                )
                bundle = ReportBundleAction().export(
                    bundle_dir=html_output_path.parent,
                    model=model,
                    findings=findings,
                    trend=trend,
                    topology_snapshot=topology_snapshot,
                    suppressed_findings=suppressed_findings,
                    html_report_path=report_path,
                )
                console.print(f"\n[bold green]Report generated:[/] {report_path}")
                console.print(f"[bold green]Bundle directory:[/] {html_output_path.parent.resolve()}")
                console.print(f"[dim]Artifacts:[/] {Path(bundle['summary']).name}, {Path(bundle['model']).name}, {Path(bundle['findings']).name}")
                if "trend" in bundle:
                    console.print(f"[dim]-[/] {Path(bundle['trend']).name}")
                if "topology" in bundle:
                    console.print(f"[dim]-[/] {Path(bundle['topology']).name}")
                if "waived_findings" in bundle:
                    console.print(f"[dim]-[/] {Path(bundle['waived_findings']).name}")
                if "certbot_systemctl_status" in bundle:
                    console.print(f"[dim]-[/] {Path(bundle['certbot_systemctl_status']).name}")
                if "certbot_renew_dry_run" in bundle:
                    console.print(f"[dim]-[/] {Path(bundle['certbot_renew_dry_run']).name}")
                if "certbot_journal" in bundle:
                    console.print(f"[dim]-[/] {Path(bundle['certbot_journal']).name}")
                if "certbot_systemctl_cat" in bundle:
                    console.print(f"[dim]-[/] {Path(bundle['certbot_systemctl_cat']).name}")
                if "certbot_certificates" in bundle:
                    console.print(f"[dim]-[/] {Path(bundle['certbot_certificates']).name}")
                if "certbot_renewal_ls" in bundle:
                    console.print(f"[dim]-[/] {Path(bundle['certbot_renewal_ls']).name}")
                exit_code = 1 if any(
                    f.severity.value in ("CRITICAL", "WARNING") for f in findings
                ) else 0
            else:
                # Report with selected format
                reporter = ReportAction(console, format_mode=fmt, show_score=score, show_explain=explain)
                
                # Only show summary table in rich/plain mode (not json)
                if fmt != "json":
                    reporter.report_server_summary(model)
                
                # Show WSS inventory if any WebSocket locations detected
                if ws_inventory:
                    reporter.report_wss_inventory(ws_inventory)
                
                exit_code = reporter.report_findings(findings)
            
            # Store in context in case user wants to pipe to recommend
            ctx.obj['findings'] = findings
            ctx.obj['model'] = model
            
            # Phase 4: Safe Fix Execution
            should_run = (fix or safe_fix)
            if should_run:
                from rich.prompt import Confirm
                
                # Determine mode
                # Defaults to dry-run unless user explicitly says "yes" or confirms interactively
                is_dry_run = dry_run
                
                if not dry_run and not yes:
                    console.print("\n[bold yellow]⚠️  You requested to apply fixes.[/]")
                    if not Confirm.ask("Do you want to proceed with applying changes?"):
                        console.print("[dim]Switching to dry-run mode...[/]")
                        is_dry_run = True
                
                # print(f"DEBUG_CLI: instantiating {SafeFixAction}")
                fixer = SafeFixAction(console, ssh, dry_run=is_dry_run)
                fix_results = fixer.run(findings)
                
                # If fixes failed, ensure we exit with error
                if any(r.status == "failed" for r in fix_results):
                    exit_code = 1
            
            sys.exit(exit_code)

    except SystemExit:
        raise
    except Exception as e:
        console.print(f"[bold red]Error:[/] {e}")
        import traceback
        traceback.print_exc()


@main.command()
@click.argument("server")
@click.option("--base", default="/var/www", help="Base directory to scan (default: /var/www)")
@click.option("--format", "fmt", type=click.Choice(["rich", "plain", "json", "html"]), default=None)
@click.option("--output", "-o", default="inventory.html", help="Output file for HTML report")
@click.pass_context
def discover(ctx: click.Context, server: str, base: str, fmt: str | None, output: str) -> None:
    """Discover filesystem projects and match with Nginx.
    
    Reveals orphaned projects that exist on disk but are not served by Nginx.
    """
    import sys
    cfg = _resolve_config(ctx, server)
    
    if fmt is None:
        fmt = "html"
        
    # Import needed classes locally to avoid circular dependencies if any
    from server_doctor.scanner.filesystem import FilesystemScanner
    from server_doctor.analyzer.app_detector import AppDetector

    try:
        with SSHConnector(cfg) as ssh:
            # 1. Get Truth (Nginx)
            with console.status(f"🔍 Scanning active Nginx config...", spinner="dots") if fmt == "rich" else contextlib.nullcontext():
                model = _scan_server(ctx, ssh)
            
            # 2. Get Inventory (Filesystem)
            fs_scanner = FilesystemScanner(ssh)
            detector = AppDetector()
            
            with console.status(f"📂 Crawling {base}...", spinner="dots") if fmt == "rich" else contextlib.nullcontext():
                candidate_paths = fs_scanner.crawl_projects(base)
                
            filesystem_projects = []
            
            # Analyze each candidate
            with console.status(f"🕵️ Analyzing {len(candidate_paths)} folders...", spinner="dots") if fmt == "rich" else contextlib.nullcontext():
                for path in candidate_paths:
                    d_scan = fs_scanner.scan_directory(path)
                    
                    # Check for composer usage to improve detection
                    composer_data = None
                    if d_scan.has_composer_json:
                        content = fs_scanner.get_file_content(f"{path}/composer.json")
                        if content:
                            try:
                                import json
                                composer_data = json.loads(content)
                            except: pass
                            
                    detection = detector.detect(d_scan, composer_data)
                    
                    # Create ProjectInfo (lightweight version)
                    filesystem_projects.append({
                        "path": path,
                        "type": detection.project_type,
                        "conf": detection.confidence,
                        "scan": d_scan
                    })

            # 3. Correlate
            # Map Nginx roots to these fs paths
            # Logic: If Nginx root is /var/www/foo/public, it matches /var/www/foo
            
            inventory = []
            
            for fs_proj in filesystem_projects:
                path = fs_proj['path']
                status = "unreferenced"
                matched_nginx_project = None
                
                # Check against Nginx projects
                for nginx_proj in model.projects:
                    # Check exact or subpath logic
                    # If nginx project path (normalized) is inside fs path or equals
                    # NginxScanner normalizes roots to project base usually.
                    if nginx_proj.path == path:
                        status = "configured"
                        matched_nginx_project = nginx_proj
                        break
                    
                    # Also check if nginx root starts with this fs path (e.g. fs=/var/www/app, nginx=/var/www/app/public)
                    if nginx_proj.path.startswith(path + "/"):
                         status = "configured"
                         matched_nginx_project = nginx_proj
                         break
                
                inventory.append({
                    "path": path,
                    "type": fs_proj['type'],
                    "status": status,
                    "nginx_project": matched_nginx_project
                })
                
            # Report
            if fmt == "html":
                unreferenced = []
                static_noise = []
                
                for item in inventory:
                    if item['status'] == 'unreferenced':
                        # Classify by type
                        if item['type'] in [ProjectType.STATIC, ProjectType.UNKNOWN]:
                            static_noise.append(item['path'])
                        else:
                            unreferenced.append(item)
                
                html_reporter = HTMLReportAction()
                report_path = html_reporter.generate(
                    model, 
                    output_path=output, 
                    unreferenced=unreferenced,
                    static_noise=static_noise
                )
                console.print(f"\n[bold green]Inventory Report generated:[/] {report_path}")
                sys.exit(0)

            reporter = ReportAction(console, format_mode=fmt)
            reporter.report_inventory(inventory, base)
            
    except Exception as e:
        console.print(f"[bold red]Error:[/] {e}")
        import traceback
        traceback.print_exc()


@main.command()
@click.argument("server")
@click.pass_context
def recommend(ctx: click.Context, server: str) -> None:
    """Get recommendations for a server.

    Provides ranked solutions (best → acceptable → risky).
    """
    cfg = _resolve_config(ctx, server)
    try:
        with SSHConnector(cfg) as ssh:
            model = _scan_server(ctx, ssh)
            
            dr_analyzer = ServerDoctorAnalyzer(model)
            auditor = ServerAuditor(model)
            findings = dr_analyzer.diagnose() + auditor.audit()
            
            engine = DecisionEngine(model, findings)
            recs = engine.recommend()
            
            reporter = ReportAction(console)
            reporter.report_recommendations(recs)
    except Exception as e:
        console.print(f"[bold red]Error:[/] {e}")


@main.command()
@click.argument("server")
@click.option("--project", "-p", help="Specific project to generate config for")
@click.option("--output", "-o", type=click.Path(), help="Output file path")
@click.pass_context
def generate(
    ctx: click.Context, server: str, project: str | None, output: str | None
) -> None:
    """Generate Nginx configuration for a server/project.

    This is read-only. Configs are written locally, not to the server.
    """
    cfg = _resolve_config(ctx, server)
    try:
        with SSHConnector(cfg) as ssh:
            model = _scan_server(ctx, ssh)
            
            gen = GenerateAction()
            # If no project specified, take first one
            proj = None
            if project:
                proj = next((p for p in model.projects if project in p.path), None)
            elif model.projects:
                proj = model.projects[0]
            
            if not proj:
                console.print("[yellow]No project found to generate config for.[/]")
                return

            # Default domain to hostname if not known
            domain = model.hostname
            config_text = gen.generate_laravel_config(proj, domain)
            
            if output:
                import pathlib
                gen.write_config(config_text, pathlib.Path(output))
                console.print(f"[green]✓ Config written to:[/] {output}")
            else:
                console.print(Panel(config_text, title="Generated Config", style="cyan"))
                
    except Exception as e:
        console.print(f"[bold red]Error:[/] {e}")


@main.command()
@click.argument("server")
@click.option("--config", "-c", "config_file", type=click.Path(exists=True), required=True, help="Config file to apply")
@click.option("--target", "-t", required=True, help="Target path on server")
@click.option("--backup/--no-backup", default=True, help="Backup existing configs first")
@click.pass_context
def apply(
    ctx: click.Context, server: str, config_file: str, target: str, backup: bool
) -> None:
    """Apply configuration changes to a server.

    ⚠️  WARNING: This modifies the server!
    """
    cfg = _resolve_config(ctx, server)
    try:
        with SSHConnector(cfg) as ssh:
            apply_act = ApplyAction(ssh)
            import pathlib
            config_content = pathlib.Path(config_file).read_text()
            
            console.print(f"[bold yellow]⚠️  Applying config to {target}...[/]")
            if click.confirm("Are you sure you want to proceed?"):
                result = apply_act.apply_config(config_content, target, backup=backup)
                if result.success:
                    console.print("[bold green]✓ Successfully applied and reloaded nginx![/]")
                else:
                    console.print(f"[bold red]Error:[/] {result.error}")
                    if result.nginx_test_output:
                        console.print(f"[dim]Nginx test output:[/]\n{result.nginx_test_output}")
    except Exception as e:
        console.print(f"[bold red]Error:[/] {e}")


@main.group()
def config() -> None:
    """Manage server connection profiles."""
    pass


@config.command("add")
@click.argument("name")
@click.option("--host", "-h", required=True, help="Server hostname or IP")
@click.option("--user", "-u", default="root", help="SSH username")
@click.option("--port", "-p", default=22, help="SSH port")
@click.option("--password", "-pass", help="SSH password")
@click.option("--key", "-k", type=click.Path(), help="Path to SSH private key")
@click.option("--sudo/--no-sudo", default=True, help="Use sudo for commands")
@click.pass_context
def config_add(
    ctx: click.Context, name: str, host: str, user: str, port: int, password: str | None, key: str | None, sudo: bool
) -> None:
    """Add a new server profile."""
    config_mgr = ctx.obj["config_mgr"]
    cfg = SSHConfig(host=host, user=user, port=port, password=password, key_path=key, use_sudo=sudo)
    config_mgr.add_profile(name, cfg)
    console.print(f"[bold green]✓ Added server profile:[/] {name}")


@config.command("list")
@click.pass_context
def config_list(ctx: click.Context) -> None:
    """List all server profiles."""
    config_mgr = ctx.obj["config_mgr"]
    profiles = config_mgr.list_profiles()
    if not profiles:
        console.print("[dim]No profiles configured yet.[/]")
        return
        
    for name, data in profiles.items():
        console.print(f"[bold green]{name}[/]: {data['user']}@{data['host']}:{data['port']}")


@config.command("remove")
@click.argument("name")
@click.pass_context
def config_remove(ctx: click.Context, name: str) -> None:
    """Remove a server profile."""
    config_mgr = ctx.obj["config_mgr"]
    if config_mgr.remove_profile(name):
        console.print(f"[bold green]✓ Removed profile:[/] {name}")
    else:
        console.print(f"[bold red]Error:[/] Profile {name} not found.")


@main.command()
@click.option("--port", default=8765, help="Port to listen on (default: 8765)")
@click.option("--host", default="127.0.0.1", hidden=True, help="Bind address (locked to 127.0.0.1)")
def web(port: int, host: str) -> None:
    """Start the Project Setup Wizard web UI.
    
    Runs a local web server for configuring Nginx projects via SSH.
    
    Example:
        server-doctor web --port 8765
    
    Then open: http://127.0.0.1:8765/wizard
    """
    console.print("[bold cyan]server-doctor Project Setup Wizard[/]")
    console.print()
    
    # Security: Force localhost binding
    if host != "127.0.0.1":
        console.print("[yellow]Security: Forcing bind to 127.0.0.1 (localhost only)[/]")
        host = "127.0.0.1"
    
    console.print(f"[bold]Starting server at:[/] http://{host}:{port}/wizard")
    console.print("[dim]Press Ctrl+C to stop[/]")
    console.print()
    
    from server_doctor.web.app import run_server
    run_server(host=host, port=port)


@main.command()
@click.argument("server")
@click.option("--format", "output_format", type=click.Choice(["json", "sarif", "github"]), default="json",
              help="Output format for CI/CD integration")
@click.option("--output", "-o", type=click.Path(), help="Output file (default: stdout)")
@click.option("--fail-on-warning", is_flag=True, help="Exit with error on warnings (not just critical)")
@click.option("--timeout", default=300, help="Scan timeout in seconds")
@click.pass_context
def ci(
    ctx: click.Context,
    server: str,
    output_format: str,
    output: str | None,
    fail_on_warning: bool,
    timeout: int,
) -> None:
    """CI/CD scan mode with machine-readable output.
    
    Designed for integration with GitHub Actions, GitLab CI, Jenkins, etc.
    
    Exit codes:
        0 = Success (no issues or only info)
        1 = Warnings found (with --fail-on-warning)
        2 = Critical issues found
        3 = Error during scan
    
    Examples:
        server-doctor ci myserver --format json
        server-doctor ci myserver --format sarif -o results.sarif
        server-doctor ci myserver --format github --fail-on-warning
    """
    import time
    from server_doctor.actions.cicd_formatter import CICDFormatter, SARIFFormatter
    
    cfg = _resolve_config(ctx, server)
    start_time = time.time()
    
    try:
        with SSHConnector(cfg) as ssh:
            # Run scan
            findings = _run_full_scan(ctx, ssh, cfg, timeout)
            scan_duration = time.time() - start_time
            
            # Format output
            if output_format == "sarif":
                result = SARIFFormatter.format(findings)
            elif output_format == "github":
                # GitHub Actions annotation format
                result = CICDFormatter.format_findings(findings, server_name=server, scan_duration=scan_duration)
                # Add GitHub-specific fields
                result["github"] = {
                    "annotations": result.get("annotations", []),
                    "summary": f"Found {result['summary']['critical']} critical, {result['summary']['warning']} warnings"
                }
            else:
                result = CICDFormatter.format_findings(findings, server_name=server, scan_duration=scan_duration)
            
            # Output
            output_json = json.dumps(result, indent=2 if output_format == "json" else None)
            
            if output:
                Path(output).write_text(output_json)
                console.print(f"[green]Results written to {output}[/]")
            else:
                print(output_json)
            
            # Exit code
            exit_code = CICDFormatter.get_exit_code(findings, fail_on_warning)
            sys.exit(exit_code)
            
    except Exception as e:
        error_result = {
            "error": str(e),
            "timestamp": datetime.datetime.utcnow().isoformat() + "Z",
            "findings": [],
            "summary": {"error": True, "message": str(e)},
        }
        print(json.dumps(error_result))
        sys.exit(3)


def _run_full_scan(ctx, ssh, cfg: SSHConfig, timeout: int) -> list:
    """Run complete scan and return findings."""
    # Get the model using the same logic as other commands
    model = _scan_server(ctx, ssh)
    
    # Run diagnosis like the check command
    dr_analyzer = ServerDoctorAnalyzer(model)
    from server_doctor.analyzer.wss_auditor import WSSAuditor
    from server_doctor.analyzer.docker_auditor import DockerAuditor
    from server_doctor.analyzer.node_auditor import NodeAuditor
    from server_doctor.analyzer.systemd_auditor import SystemdAuditor
    from server_doctor.analyzer.redis_auditor import RedisAuditor
    from server_doctor.analyzer.worker_auditor import WorkerAuditor
    from server_doctor.analyzer.mysql_auditor import MySQLAuditor
    from server_doctor.analyzer.firewall_auditor import FirewallAuditor
    from server_doctor.analyzer.telemetry_auditor import TelemetryAuditor
    from server_doctor.analyzer.security_baseline_auditor import SecurityBaselineAuditor
    from server_doctor.analyzer.vulnerability_auditor import VulnerabilityAuditor
    from server_doctor.analyzer.network_surface_auditor import NetworkSurfaceAuditor
    from server_doctor.analyzer.path_conflict_auditor import PathConflictAuditor
    from server_doctor.analyzer.runtime_drift_auditor import RuntimeDriftAuditor
    from server_doctor.analyzer.certbot_auditor import CertbotAuditor

    wss_auditor = WSSAuditor(model)
    def _safe_audit(label: str, fn):
        try:
            return fn()
        except Exception:
            return []
    
    legacy_findings = dr_analyzer.diagnose(
        additional_findings=(
            ServerAuditor(model).audit()
            + _safe_audit("WSS", wss_auditor.audit)
            + _safe_audit("Docker", DockerAuditor(model).audit)
            + _safe_audit("Node", NodeAuditor(model).audit)
            + _safe_audit("Systemd", SystemdAuditor(model).audit)
            + _safe_audit("Redis", RedisAuditor(model).audit)
            + _safe_audit("Worker", WorkerAuditor(model).audit)
            + _safe_audit("MySQL", MySQLAuditor(model).audit)
            + _safe_audit("Firewall", FirewallAuditor(model).audit)
            + _safe_audit("Telemetry", TelemetryAuditor(model).audit)
            + _safe_audit("SecurityBaseline", SecurityBaselineAuditor(model).audit)
            + _safe_audit("Vulnerability", VulnerabilityAuditor(model).audit)
            + _safe_audit("NetworkSurface", NetworkSurfaceAuditor(model).audit)
            + _safe_audit("PathConflict", PathConflictAuditor(model).audit)
            + _safe_audit("RuntimeDrift", RuntimeDriftAuditor(model).audit)
            + _safe_audit("Certbot", CertbotAuditor(model).audit)
        )
    )

    # Keep check command strict by running modular checks by default.
    from server_doctor.checks import CheckContext, run_checks
    from server_doctor.engine.deduplication import deduplicate_findings

    check_ctx = CheckContext(
        model=model,
        ssh=ssh,
        laravel_enabled=True,
        ports_enabled=True,
        security_enabled=True,
        phpfpm_enabled=True,
        performance_enabled=True,
        devops_enabled=True,
    )
    findings = deduplicate_findings(legacy_findings + run_checks(check_ctx))
    
    return findings


@main.group()
def notify() -> None:
    """Configure notifications and alerts."""
    pass


@notify.command("slack")
@click.option("--webhook", required=True, help="Slack webhook URL")
@click.option("--channel", help="Slack channel (e.g., #alerts)")
@click.option("--only-critical", is_flag=True, help="Only send critical findings")
@click.pass_context
def slack_setup(ctx: click.Context, webhook: str, channel: str | None, only_critical: bool) -> None:
    """Configure Slack notifications for scan results."""
    from server_doctor.config import ConfigManager
    
    config_mgr = ctx.obj["config_mgr"]
    config_mgr.set_notification("slack", {
        "webhook": webhook,
        "channel": channel,
        "only_critical": only_critical,
    })
    console.print("[bold green]✓ Slack notifications configured[/]")


@notify.command("test")
@click.pass_context
def notify_test(ctx: click.Context) -> None:
    """Send a test notification to verify configuration."""
    from server_doctor.integrations.notifier import NotificationManager
    from server_doctor.model.finding import Finding
    from server_doctor.model.evidence import Evidence, Severity
    
    config_mgr = ctx.obj["config_mgr"]
    notifier = NotificationManager(config_mgr)
    
    test_finding = Finding(
        id="TEST-001",
        severity=Severity.WARNING,
        confidence=1.0,
        condition="Test notification",
        cause="This is a test to verify notification settings.",
        evidence=[
            Evidence(
                source_file="server-doctor",
                line_number=0,
                excerpt="Test notification payload",
                command="server-doctor notify test",
            )
        ],
        treatment="No action needed",
        impact=["Verify notification integration"],
    )
    
    success = notifier.send_notification([test_finding])
    if success:
        console.print("[bold green]✓ Test notification sent successfully[/]")
    else:
        console.print("[bold red]✗ Failed to send test notification[/]")


@main.group()
def daemon() -> None:
    """Continuous monitoring and scheduled scanning."""
    pass


@daemon.command("start")
@click.option("--interval", default=3600, help="Scan interval in seconds (default: 1 hour)")
@click.option("--servers", "-s", multiple=True, help="Servers to monitor (default: all)")
@click.option("--pid-file", default="/tmp/server-doctor.pid", help="PID file location")
@click.option("--log-file", help="Log file (default: stdout)")
@click.pass_context
def daemon_start(
    ctx: click.Context,
    interval: int,
    servers: tuple[str, ...],
    pid_file: str,
    log_file: str | None,
) -> None:
    """Start the monitoring daemon.
    
    Runs continuous scans and sends alerts for new issues.
    
    Example:
        server-doctor daemon start --interval 3600 --servers web1,web2
    """
    from server_doctor.daemon.monitor import MonitoringDaemon
    
    config_mgr = ctx.obj["config_mgr"]
    
    daemon = MonitoringDaemon(
        config_mgr=config_mgr,
        interval=interval,
        servers=list(servers) if servers else None,
        pid_file=pid_file,
        log_file=log_file,
    )
    
    try:
        daemon.start()
    except KeyboardInterrupt:
        console.print("\n[yellow]Shutting down daemon...[/]")
        daemon.stop()


@daemon.command("stop")
@click.option("--pid-file", default="/tmp/server-doctor.pid", help="PID file location")
def daemon_stop(pid_file: str) -> None:
    """Stop the monitoring daemon."""
    from server_doctor.daemon.monitor import MonitoringDaemon
    
    daemon = MonitoringDaemon(pid_file=pid_file)
    daemon.stop()
    console.print("[bold green]✓ Daemon stopped[/]")


@daemon.command("status")
@click.option("--pid-file", default="/tmp/server-doctor.pid", help="PID file location")
def daemon_status(pid_file: str) -> None:
    """Check if daemon is running."""
    from server_doctor.daemon.monitor import MonitoringDaemon
    
    daemon = MonitoringDaemon(pid_file=pid_file)
    if daemon.is_running():
        info = daemon.get_info()
        console.print(f"[green]Daemon is running[/]")
        console.print(f"  PID: {info.get('pid')}")
        console.print(f"  Started: {info.get('started')}")
        console.print(f"  Servers: {info.get('servers', 'all')}")
        console.print(f"  Interval: {info.get('interval')}s")
    else:
        console.print("[red]Daemon is not running[/]")


if __name__ == "__main__":
    main()
