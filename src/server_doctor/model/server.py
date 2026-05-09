"""Server model dataclasses - Core data structures representing server state."""

from dataclasses import dataclass, field
from enum import Enum

# ... (rest of the code remains the same)


class ProjectType(Enum):
    """Detected project type."""

    LARAVEL = "laravel"
    PHP_MVC = "php_mvc"
    STATIC = "static"
    REACT_SPA = "react_spa"
    VUE_SPA = "vue_spa"
    NODE_API = "node_api"
    NODE_SSR = "node_ssr"
    REACT_STATIC_BUILD = "react_static_build"
    REACT_SOURCE = "react_source"
    NEXTJS = "nextjs"
    NUXT = "nuxt"
    DOCKERIZED_APP = "dockerized_app"
    REVERSE_PROXY = "reverse_proxy"
    REACT_FRONTEND = "react_frontend"
    WEBSOCKET_SERVICE = "websocket_service"
    UNKNOWN = "unknown"


class CapabilityLevel(Enum):
    """Capability level for a service/scanner."""

    FULL = "full"
    LIMITED = "limited"
    NONE = "none"


class ServiceState(Enum):
    """Runtime state of a service."""

    RUNNING = "running"
    STOPPED = "stopped"
    NOT_INSTALLED = "not_installed"
    UNKNOWN = "unknown"


class CapabilityReason(Enum):
    """Reason for a specific capability level."""

    PERMISSION_DENIED = "permission_denied"
    BINARY_MISSING = "binary_missing"
    SOCKET_MISSING = "socket_missing"
    DAEMON_UNREACHABLE = "daemon_unreachable"
    TIMEOUT = "timeout"
    UNKNOWN = "unknown"


@dataclass
class OSInfo:
    """Operating system information."""

    name: str  # Ubuntu, Debian, CentOS, etc.
    version: str  # 22.04, 11, 9, etc.
    codename: str | None = None  # jammy, bullseye, etc.

    @property
    def full_name(self) -> str:
        """Get full OS name with version."""
        if self.codename:
            return f"{self.name} {self.version} ({self.codename})"
        return f"{self.name} {self.version}"


@dataclass
class LocationBlock:
    """Nginx location block."""

    path: str  # /api, /static, ~* \.php$
    root: str | None = None
    alias: str | None = None
    try_files: str | None = None
    autoindex: bool = False
    fastcgi_pass: str | None = None
    proxy_pass: str | None = None
    source_file: str = ""  # Which config file this came from
    line_number: int = 0  # For evidence tracking
    
    # Headers defined with add_header
    headers: dict[str, str] = field(default_factory=dict)
    add_header_inherit: str | None = None
    auth_basic: str | None = None
    include_files: list[str] = field(default_factory=list)
    allow_rules: list[str] = field(default_factory=list)
    deny_rules: list[str] = field(default_factory=list)

    
    # WebSocket / Reverse Proxy specific
    proxy_http_version: str | None = None  # "1.1" required for WS
    proxy_set_headers: dict[str, str] = field(default_factory=dict)  # Upgrade, Connection, Host, etc.
    proxy_buffering: str | None = None  # "on" or "off"
    proxy_read_timeout: int | None = None  # seconds
    proxy_send_timeout: int | None = None  # seconds
    return_directive: str | None = None
    stub_status: bool = False
    
    # Nested locations
    locations: list["LocationBlock"] = field(default_factory=list)


@dataclass
class ServerBlock:
    """Nginx server block."""

    server_names: list[str] = field(default_factory=list)
    listen: list[str] = field(default_factory=list)  # 80, 443 ssl, etc.
    root: str | None = None
    autoindex: bool = False
    index: list[str] = field(default_factory=list)
    locations: list[LocationBlock] = field(default_factory=list)
    ssl_enabled: bool = False
    ssl_certificate: str | None = None
    ssl_certificate_key: str | None = None
    source_file: str = ""  # Which config file this came from
    line_number: int = 0  # For evidence tracking
    
    # Headers defined with add_header
    headers: dict[str, str] = field(default_factory=dict)
    add_header_inherit: str | None = None
    auth_basic: str | None = None
    include_files: list[str] = field(default_factory=list)
    allow_rules: list[str] = field(default_factory=list)
    deny_rules: list[str] = field(default_factory=list)
    http2_enabled: bool | None = None


    @property
    def is_default_server(self) -> bool:
        """Check if this is a default/catch-all server."""
        return "_" in self.server_names or "default_server" in " ".join(self.listen)


@dataclass
class UpstreamBlock:
    """Nginx upstream block for load balancing / proxying."""
    
    name: str  # upstream name (e.g., "websocket_backend")
    servers: list[str] = field(default_factory=list)  # 127.0.0.1:6001, unix:/path/to/sock
    source_file: str = ""
    line_number: int = 0


@dataclass
class NginxInfo:
    """Nginx server information."""

    version: str
    config_path: str  # /etc/nginx/nginx.conf
    servers: list[ServerBlock] = field(default_factory=list)
    upstreams: list[UpstreamBlock] = field(default_factory=list)  # All upstream {} blocks
    includes: list[str] = field(default_factory=list)  # All included config files
    skipped_includes: list[str] = field(default_factory=list)  # Included files that were skipped
    skipped_paths: list[str] = field(default_factory=list)  # Dynamic paths like $1 skipped during scan
    
    # Global/HTTP context headers
    http_headers: dict[str, str] = field(default_factory=dict)
    http_add_header_inherit: str | None = None
    
    has_connection_upgrade_map: bool = False  # True if map $http_upgrade $connection_upgrade detected
    raw: str = ""  # Full nginx -T output for reference
    
    # Phase 16: Docker-Awareness
    mode: str = "HOST"  # HOST, DOCKER, NONE
    container_id: str | None = None
    path_mapping: dict[str, str] = field(default_factory=dict)  # container_path -> host_path
    virtual_files: dict[str, str] = field(default_factory=dict)  # path -> content

    def translate_path(self, container_path: str) -> str:
        """Translate a container path to a host path using bind mounts."""
        if not self.path_mapping or self.mode != "DOCKER":
            return container_path
            
        cp = container_path.rstrip("/")
        # Try exact match first
        if cp in self.path_mapping:
            return self.path_mapping[cp]
            
        # Try prefix match (longest prefix first)
        sorted_prefixes = sorted(self.path_mapping.keys(), key=len, reverse=True)
        for prefix in sorted_prefixes:
            if cp.startswith(prefix + "/"):
                return self.path_mapping[prefix] + cp[len(prefix):]
        
        return container_path


@dataclass
class PHPInfo:
    """PHP installation information."""

    versions: list[str] = field(default_factory=list)  # 8.2.10, 8.1.25
    default_version: str | None = None
    sockets: list[str] = field(default_factory=list)  # /run/php/php8.2-fpm.sock
    fpm_configs: list[str] = field(default_factory=list)  # Pool config paths


@dataclass
class ServiceStatus:
    """Status and capability information for a service."""

    capability: CapabilityLevel
    state: ServiceState = ServiceState.UNKNOWN
    reason: CapabilityReason | None = None
    version: str | None = None
    listening_ports: list[int] = field(default_factory=list)


@dataclass
class CorrelationEvidence:
    """Evidence for Nginx-to-Entity route correlation."""

    nginx_location: str  # file path:line
    proxy_target_raw: str  # http://127.0.0.1:8080
    proxy_target_normalized: str  # 127.0.0.1:8080
    matched_entity: str  # Container name or PID
    match_confidence: str  # HIGH, MED, LOW


@dataclass
class DockerPort:
    """Docker port mapping."""

    container_port: int
    host_ip: str = "0.0.0.0"
    host_port: int | None = None
    proto: str = "tcp"


@dataclass
class DockerContainer:
    """Information about a Docker container."""

    name: str
    image: str
    status: str
    id: str | None = None
    main_pid: int | None = None
    restart_count: int = 0
    ports: list[DockerPort] = field(default_factory=list)
    mounts: list[dict[str, str]] = field(default_factory=list)

    def translate_path(self, container_path: str) -> str:
        """Translate a container-internal path to a host path."""
        if not container_path:
            return container_path
            
        cp = container_path.rstrip("/")
        # Try exact match first
        for m in self.mounts:
            if m.get("type") == "bind":
                src = m.get("source")
                dst = m.get("destination", "").rstrip("/")
                if src and dst == cp:
                    return src
        
        # Try prefix match (longest destination path first)
        sorted_mounts = sorted(
            [m for m in self.mounts if m.get("type") == "bind"], 
            key=lambda x: len(x.get("destination", "")), 
            reverse=True
        )
        for m in sorted_mounts:
            src = m.get("source")
            dst = m.get("destination", "").rstrip("/")
            if src and dst and cp.startswith(dst + "/"):
                return src + cp[len(dst):]
        
        return container_path


@dataclass
class NodeProcess:
    """Information about a running Node.js process."""

    pid: int
    cmdline: str
    cwd: str
    container_id: str | None = None
    listening_ports: list[int] = field(default_factory=list)


@dataclass
class ServicesModel:
    """Model representing secondary services on the server."""

    docker: ServiceStatus = field(default_factory=lambda: ServiceStatus(capability=CapabilityLevel.NONE))
    docker_containers: list[DockerContainer] = field(default_factory=list)
    
    mysql: ServiceStatus = field(default_factory=lambda: ServiceStatus(capability=CapabilityLevel.NONE))
    mysql_config_detected: bool = False
    mysql_bind_addresses: list[str] = field(default_factory=list)
    
    node: ServiceStatus = field(default_factory=lambda: ServiceStatus(capability=CapabilityLevel.NONE))
    node_processes: list[NodeProcess] = field(default_factory=list)

    firewall: str = "unknown"  # present, not_detected, unknown
    firewall_ufw_enabled: bool | None = None
    firewall_ufw_default_incoming: str | None = None  # allow, deny, unknown
    firewall_rules: list[str] = field(default_factory=list)


@dataclass
class ProjectInfo:
    """Detected project information."""

    path: str  # /var/www/chatduel
    type: ProjectType
    confidence: float  # 0.0 - 1.0
    public_path: str | None = None  # /var/www/chatduel/public
    assets_paths: list[str] = field(default_factory=list)
    framework_version: str | None = None  # Laravel 10.x
    env_path: str | None = None  # Path to .env if exists
    env_permissions: str | None = None  # Numeric mode (e.g. 600) when available
    composer_json: dict | None = None  # Parsed composer.json
    php_socket: str | None = None  # FPM socket used by this project
    docker_container: str | None = None  # Linked container name if applicable
    discovery_source: str = "nginx"  # nginx, docker, node
    correlation: list[CorrelationEvidence] = field(default_factory=list)


@dataclass
class SystemdService:
    """Systemd service unit information."""

    name: str
    state: str  # active, inactive, failed
    substate: str  # running, exited, dead
    restart_count: int = 0  # Best-effort (NRestarts or heuristic)
    main_pid: int | None = None
    exec_start: str | None = None
    ports: list[int] = field(default_factory=list)


@dataclass
class RedisInstance:
    """Redis instance information."""

    port: int
    state: ServiceState
    config_path: str | None = None
    auth_enabled: bool | None = None  # True=Auth, False=No Auth, None=Unknown
    bind_addresses: list[str] = field(default_factory=list)
    protected_mode: bool = False


@dataclass
class WorkerProcess:
    """Background worker process information."""

    pid: int
    cmdline: str
    queue_type: str  # laravel, node, custom
    backend: str = "unknown"  # redis, db, sqs


@dataclass
class RuntimeModel:
    """Runtime topology and service state."""
    
    systemd: ServiceStatus = field(default_factory=lambda: ServiceStatus(capability=CapabilityLevel.NONE))
    systemd_services: list[SystemdService] = field(default_factory=list)

    redis: ServiceStatus = field(default_factory=lambda: ServiceStatus(capability=CapabilityLevel.NONE))
    redis_instances: list[RedisInstance] = field(default_factory=list)

    workers: ServiceStatus = field(default_factory=lambda: ServiceStatus(capability=CapabilityLevel.NONE))
    worker_processes: list[WorkerProcess] = field(default_factory=list)
    scheduler_detected: bool = False
    scheduler_type: str | None = None  # cron, systemd-timer


@dataclass
class DiskUsage:
    """Disk utilization for a mountpoint."""

    mount: str
    total_gb: float
    used_gb: float
    used_percent: float
    inode_total: int | None = None
    inode_used_percent: float | None = None


@dataclass
class SecurityBaselineModel:
    """Baseline OS/security posture snapshot."""

    package_manager: str | None = None  # apt, dnf, yum, unknown
    ssh_permit_root_login: str | None = None
    ssh_password_authentication: str | None = None
    pending_updates_total: int | None = None
    pending_security_updates: int | None = None
    reboot_required: bool = False


@dataclass
class OpsPostureModel:
    """Extended operational posture signals for host and containers."""

    backup_tools: list[str] = field(default_factory=list)
    backup_recent_files: list[str] = field(default_factory=list)
    backup_last_age_days: float | None = None

    fail2ban_active: bool | None = None
    unattended_upgrades_enabled: bool | None = None
    unattended_upgrades_active: bool | None = None
    ntp_synchronized: bool | None = None
    auditd_active: bool | None = None

    apparmor_enabled: bool | None = None
    selinux_mode: str | None = None

    ssh_pubkey_authentication: str | None = None
    ssh_permit_empty_passwords: str | None = None
    ssh_max_auth_tries: int | None = None
    ssh_allow_tcp_forwarding: str | None = None

    docker_socket_mode: str | None = None
    docker_privileged_containers: list[str] = field(default_factory=list)
    docker_host_network_containers: list[str] = field(default_factory=list)
    docker_host_pid_containers: list[str] = field(default_factory=list)
    docker_root_user_containers: list[str] = field(default_factory=list)
    docker_no_memory_limit_containers: list[str] = field(default_factory=list)
    docker_no_readonly_rootfs_containers: list[str] = field(default_factory=list)


@dataclass
class VulnerabilityModel:
    """Package vulnerability posture from distro security metadata."""

    provider: str = "unknown"  # apt, dnf, yum, unknown
    cve_ids: list[str] = field(default_factory=list)
    advisory_ids: list[str] = field(default_factory=list)
    affected_packages: list[str] = field(default_factory=list)


@dataclass
class CertbotModel:
    """Certbot usage and certificate-renewal posture."""

    installed: bool | None = None
    service_failed: bool = False
    timer_active: bool = False
    timer_enabled: bool = False
    uses_letsencrypt_certs: bool = False
    https_detected: bool = False
    min_days_to_expiry: int | None = None
    active_cert_paths: list[str] = field(default_factory=list)
    renew_dry_run_output: str | None = None
    systemctl_status_output: str | None = None
    journal_output: str | None = None
    unit_cat_output: str | None = None
    certificates_output: str | None = None
    renewal_dir_listing: str | None = None


@dataclass
class NetworkEndpoint:
    """Live listening endpoint on the host."""

    protocol: str  # tcp or udp
    address: str
    port: int
    pid: int | None = None
    program: str | None = None
    service: str | None = None
    public_exposed: bool = False


@dataclass
class NetworkSurfaceModel:
    """Host network exposure snapshot."""

    endpoints: list[NetworkEndpoint] = field(default_factory=list)


@dataclass
class TLSCertificateStatus:
    """TLS certificate metadata extracted from active cert paths."""

    path: str
    issuer: str | None = None
    subject: str | None = None
    expires_at: str | None = None
    days_remaining: int | None = None
    sans: list[str] = field(default_factory=list)
    parse_ok: bool = False


@dataclass
class TLSStatusModel:
    """TLS certificate posture snapshot."""

    certificates: list[TLSCertificateStatus] = field(default_factory=list)


@dataclass
class UpstreamProbeResult:
    """Optional active probe result for upstream/local backend targets."""

    target: str
    protocol: str = "tcp"  # tcp/http/https
    reachable: bool = False
    latency_ms: float | None = None
    detail: str | None = None
    scope: str = "host"  # host, nginx_container, unknown
    status: str = "UNKNOWN"  # OPEN, BLOCKED, UNKNOWN
    tcp_ok: bool | None = None
    http_code: int | None = None
    ws_code: int | None = None
    ws_status: str | None = None  # 101, 426, timeout, fail, n/a
    ws_detail: str | None = None
    ws_path: str | None = None


@dataclass
class TelemetryModel:
    """Host-level telemetry snapshot."""

    cpu_cores: int | None = None
    load_1: float | None = None
    load_5: float | None = None
    load_15: float | None = None
    mem_total_mb: int | None = None
    mem_available_mb: int | None = None
    swap_total_mb: int | None = None
    swap_free_mb: int | None = None
    disks: list[DiskUsage] = field(default_factory=list)


@dataclass
class LogsModel:
    """Recent log/error posture snapshot."""

    journal_errors_24h: int | None = None
    journal_oom_events_24h: int | None = None
    nginx_error_counts: dict[str, int] = field(default_factory=dict)
    nginx_error_samples: list[str] = field(default_factory=list)
    php_fpm_error_counts: dict[str, int] = field(default_factory=dict)
    php_fpm_error_samples: list[str] = field(default_factory=list)
    docker_crashloop_containers: list[str] = field(default_factory=list)
    docker_error_samples: list[str] = field(default_factory=list)
    collection_status: dict[str, str] = field(default_factory=dict)
    collection_notes: dict[str, str] = field(default_factory=dict)


@dataclass
class StorageMountModel:
    """Storage mount status snapshot."""

    mount: str
    total_gb: float
    used_gb: float
    used_percent: float
    inode_used_percent: float | None = None
    read_only: bool = False


@dataclass
class StorageModel:
    """Storage health posture snapshot."""

    mounts: list[StorageMountModel] = field(default_factory=list)
    read_only_mounts: list[str] = field(default_factory=list)
    failed_mount_units: list[str] = field(default_factory=list)
    io_wait_percent: float | None = None
    io_error_samples: list[str] = field(default_factory=list)
    collection_status: dict[str, str] = field(default_factory=dict)
    collection_notes: dict[str, str] = field(default_factory=dict)


@dataclass
class ResourcesModel:
    """Runtime resource pressure snapshot."""

    cpu_cores: int | None = None
    load_1: float | None = None
    load_5: float | None = None
    load_15: float | None = None
    mem_total_mb: int | None = None
    mem_available_mb: int | None = None
    swap_total_mb: int | None = None
    swap_free_mb: int | None = None
    oom_events_24h: int | None = None
    oom_samples: list[str] = field(default_factory=list)
    top_cpu_processes: list[str] = field(default_factory=list)
    top_mem_processes: list[str] = field(default_factory=list)
    psi_cpu_some_avg10: float | None = None
    psi_memory_some_avg10: float | None = None
    psi_io_some_avg10: float | None = None
    collection_status: dict[str, str] = field(default_factory=dict)
    collection_notes: dict[str, str] = field(default_factory=dict)


@dataclass
class KernelLimitsModel:
    """Kernel/sysctl/limits posture snapshot."""

    nofile_soft: int | None = None
    nofile_hard: int | None = None
    fs_file_max: int | None = None
    somaxconn: int | None = None
    tcp_max_syn_backlog: int | None = None
    ip_local_port_range_start: int | None = None
    ip_local_port_range_end: int | None = None
    tcp_fin_timeout: int | None = None
    netdev_max_backlog: int | None = None
    nginx_worker_connections: int | None = None
    nginx_worker_processes: int | None = None
    collection_status: dict[str, str] = field(default_factory=dict)
    collection_notes: dict[str, str] = field(default_factory=dict)


@dataclass
class DependencyManagerStatus:
    """Dependency manager detection and upgrade signal for a repository."""

    manager: str  # npm, composer, pip, etc.
    ecosystem: str  # Human-readable ecosystem label
    detected_files: list[str] = field(default_factory=list)
    status: str = "detected"  # detected, checked, unavailable, unsupported, error
    check_command: str | None = None
    outdated_count: int | None = None
    sample: list[str] = field(default_factory=list)
    audit_command: str | None = None
    vulnerability_count: int | None = None
    vulnerability_summary: str | None = None
    vulnerability_sample: list[str] = field(default_factory=list)
    error: str | None = None


@dataclass
class SupplyChainRepoModel:
    """Repo-aware supply-chain scan summary for a single repository path."""

    path: str
    ci_workflows: list[str] = field(default_factory=list)
    ci_system_files: list[str] = field(default_factory=list)  # .gitlab-ci.yml, Jenkinsfile
    lockfiles: list[str] = field(default_factory=list)
    manifests: list[str] = field(default_factory=list)  # package.json, composer.json, etc.
    docker_files: list[str] = field(default_factory=list)  # Dockerfile*, docker-compose*.yml
    dependency_managers: list[DependencyManagerStatus] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)


@dataclass
class SupplyChainModel:
    """Supply-chain + CI/CD metadata aggregated across one or more repos."""

    enabled: bool = False
    repo_paths: list[str] = field(default_factory=list)
    repos: list[SupplyChainRepoModel] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)


@dataclass
class HttpProbeResult:
    """Observed behavior for a public HTTP/HTTPS endpoint or sensitive path."""

    url: str
    method: str
    status_code: int | None
    final_url: str | None
    redirect_chain: list[str]
    headers: dict[str, str]
    body_sample: str | None
    error: str | None
    elapsed_ms: int | None
    tls_subject: str | None = None
    tls_issuer: str | None = None
    tls_not_after: str | None = None


@dataclass
class HttpProbeModel:
    """Live endpoint probe results."""

    enabled: bool = False
    results: list[HttpProbeResult] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)


@dataclass
class PhpFpmDeepModel:
    """Deep PHP-FPM socket, service, and runtime posture."""

    enabled: bool = False
    socket_exists: dict[str, bool] = field(default_factory=dict)
    socket_accessible: dict[str, bool | None] = field(default_factory=dict)
    service_states: dict[str, str] = field(default_factory=dict)
    pool_users: dict[str, str] = field(default_factory=dict)
    pool_groups: dict[str, str] = field(default_factory=dict)
    cli_version: str | None = None
    fpm_version: str | None = None
    opcache_enabled: bool | None = None
    slowlog_enabled: bool | None = None
    dangerous_functions_disabled: bool | None = None
    upload_max_filesize_mb: int | None = None
    post_max_size_mb: int | None = None
    memory_limit_mb: int | None = None
    notes: list[str] = field(default_factory=list)


@dataclass
class LaravelRuntimeProject:
    """Runtime facts for one detected Laravel project."""

    path: str
    env_path: str | None = None
    env: dict[str, str | None] = field(default_factory=dict)
    queue_worker_running: bool | None = None
    scheduler_detected: bool | None = None
    failed_jobs_count: int | None = None
    horizon_installed: bool = False
    horizon_running: bool | None = None
    octane_installed: bool = False
    octane_running: bool | None = None
    recent_critical_log_lines: list[str] = field(default_factory=list)
    storage_writable: bool | None = None
    cache_writable: bool | None = None
    public_storage_symlink: bool | None = None
    config_cached: bool | None = None
    routes_cached: bool | None = None
    views_cached: bool | None = None
    migrations_pending: bool | None = None
    env_readable: bool = True


@dataclass
class LaravelRuntimeModel:
    """Aggregated Laravel runtime posture."""

    enabled: bool = False
    projects: list[LaravelRuntimeProject] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)


@dataclass
class NodeRuntimeProcess:
    """Runtime facts for a Node/PM2/systemd process."""

    name: str
    pid: int | None = None
    manager: str = "unknown"
    status: str = "unknown"
    cwd: str | None = None
    user: str | None = None
    host: str | None = None
    port: int | None = None
    restart_count: int | None = None
    memory_mb: int | None = None


@dataclass
class NodeRuntimeModel:
    """Node deployment runtime posture."""

    enabled: bool = False
    processes: list[NodeRuntimeProcess] = field(default_factory=list)
    listeners: list[NetworkEndpoint] = field(default_factory=list)
    build_paths: list[str] = field(default_factory=list)
    missing_build_paths: list[str] = field(default_factory=list)
    missing_manifest_paths: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)


@dataclass
class MySQLDeepModel:
    """Deep MySQL/MariaDB posture."""

    enabled: bool = False
    installed: bool | None = None
    service_state: str | None = None
    bind_addresses: list[str] = field(default_factory=list)
    root_remote_login: bool | None = None
    anonymous_users: bool | None = None
    recent_backup_evidence: list[str] = field(default_factory=list)
    disk_usage_percent: float | None = None
    binary_logs_gb: float | None = None
    slow_query_log_enabled: bool | None = None
    max_connections: int | None = None
    current_connections: int | None = None
    crashed_tables: list[str] = field(default_factory=list)
    buffer_pool_mb: int | None = None
    notes: list[str] = field(default_factory=list)


@dataclass
class RedisDeepModel:
    """Deep Redis posture."""

    enabled: bool = False
    instances: list[RedisInstance] = field(default_factory=list)
    service_state: str | None = None
    maxmemory_mb: int | None = None
    used_memory_mb: int | None = None
    eviction_policy: str | None = None
    persistence_enabled: bool | None = None
    scanner_available: bool = True
    notes: list[str] = field(default_factory=list)


@dataclass
class DnsTlsDomain:
    """DNS and TLS facts for one domain."""

    domain: str
    a_records: list[str] = field(default_factory=list)
    aaaa_records: list[str] = field(default_factory=list)
    scanned_public_ip: str | None = None
    cloudflare_proxied: bool = False
    certificate_subject: str | None = None
    certificate_sans: list[str] = field(default_factory=list)
    certificate_days_remaining: int | None = None
    certbot_timer_enabled: bool | None = None
    certbot_dry_run_ok: bool | None = None
    http01_blocked: bool | None = None
    port80_open: bool | None = None


@dataclass
class DnsTlsModel:
    """DNS, TLS, Cloudflare, and certbot diagnosis facts."""

    enabled: bool = False
    domains: list[DnsTlsDomain] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)


@dataclass
class BackupArtifact:
    """Backup file or directory evidence."""

    path: str
    age_days: float | None = None
    size_bytes: int | None = None
    kind: str = "unknown"
    local_only: bool | None = None
    same_disk: bool | None = None


@dataclass
class BackupReadinessModel:
    """Backup and restore-readiness posture."""

    enabled: bool = False
    production_indicators: bool = False
    tools_detected: list[str] = field(default_factory=list)
    app_backups: list[BackupArtifact] = field(default_factory=list)
    db_backups: list[BackupArtifact] = field(default_factory=list)
    restore_test_evidence: list[str] = field(default_factory=list)
    permission_denied: bool = False
    notes: list[str] = field(default_factory=list)


@dataclass
class ServerModel:
    """Complete server model - the unified view of the server state.

    All analyzers operate on this model. It is built once by the scanners
    and parsers, then passed to all analysis modules.

    This separation ensures:
    - Scanners only run commands
    - Parsers only structure data
    - Analyzers only reason about the model
    """

    hostname: str
    os: OSInfo | None = None
    nginx: NginxInfo | None = None
    nginx_status: ServiceStatus = field(default_factory=lambda: ServiceStatus(capability=CapabilityLevel.NONE))
    php: PHPInfo | None = None
    services: ServicesModel = field(default_factory=ServicesModel)
    projects: list[ProjectInfo] = field(default_factory=list)
    runtime: RuntimeModel = field(default_factory=RuntimeModel)
    telemetry: TelemetryModel = field(default_factory=TelemetryModel)
    logs: LogsModel = field(default_factory=LogsModel)
    storage: StorageModel = field(default_factory=StorageModel)
    resources: ResourcesModel = field(default_factory=ResourcesModel)
    kernel_limits: KernelLimitsModel = field(default_factory=KernelLimitsModel)
    security_baseline: SecurityBaselineModel = field(default_factory=SecurityBaselineModel)
    ops_posture: OpsPostureModel = field(default_factory=OpsPostureModel)
    vulnerability: VulnerabilityModel = field(default_factory=VulnerabilityModel)
    certbot: CertbotModel = field(default_factory=CertbotModel)
    tls: TLSStatusModel = field(default_factory=TLSStatusModel)
    network_surface: NetworkSurfaceModel = field(default_factory=NetworkSurfaceModel)
    upstream_probes: list[UpstreamProbeResult] = field(default_factory=list)
    supply_chain: SupplyChainModel = field(default_factory=SupplyChainModel)
    http_probes: HttpProbeModel = field(default_factory=HttpProbeModel)
    php_fpm_deep: PhpFpmDeepModel = field(default_factory=PhpFpmDeepModel)
    laravel_runtime: LaravelRuntimeModel = field(default_factory=LaravelRuntimeModel)
    node_runtime: NodeRuntimeModel = field(default_factory=NodeRuntimeModel)
    mysql_deep: MySQLDeepModel = field(default_factory=MySQLDeepModel)
    redis_deep: RedisDeepModel = field(default_factory=RedisDeepModel)
    dns_tls: DnsTlsModel = field(default_factory=DnsTlsModel)
    backup_readiness: BackupReadinessModel = field(default_factory=BackupReadinessModel)
    scan_timestamp: str = ""  # ISO format timestamp
    doctor_version: str = ""
    commit_hash: str = ""

    @property
    def project_count(self) -> int:
        """Get number of detected projects."""
        return len(self.projects)

    def get_project(self, name: str) -> ProjectInfo | None:
        """Find a project by name (directory name)."""
        for project in self.projects:
            if project.path.rstrip("/").split("/")[-1] == name:
                return project
        return None
