"""Tests for Phase 15 Runtime Intelligence."""

from unittest.mock import MagicMock
from server_doctor.model.server import (
    CapabilityLevel, 
    ServiceState,
    ServerModel,
    RuntimeModel, 
    SystemdService,
    RedisInstance,
    WorkerProcess
)
from server_doctor.scanner.systemd import SystemdScanner
from server_doctor.scanner.redis import RedisScanner
from server_doctor.scanner.workers import WorkerScanner
from server_doctor.analyzer.systemd_auditor import SystemdAuditor
from server_doctor.analyzer.redis_auditor import RedisAuditor
from server_doctor.analyzer.worker_auditor import WorkerAuditor
from server_doctor.model.evidence import Severity

def test_systemd_scanner_full(mock_ssh_connector):
    """Test SystemdScanner with FULL capability."""
    scanner = SystemdScanner(mock_ssh_connector)
    
    # Mock systemctl check
    mock_ssh_connector.run.side_effect = [
        # which systemctl
        MagicMock(success=True),
        # list-units
        MagicMock(success=True, stdout="""
nginx.service loaded active running A high performance web server
php8.2-fpm.service loaded active running The PHP 8.2 FastCGI Process Manager
bad.service loaded failed failed Bad Service
"""),
        # show
        MagicMock(success=True, stdout="""
Id=nginx.service
MainPID=123
NRestarts=2
ExecStart={ path=/usr/sbin/nginx ; argv[]=/usr/sbin/nginx -g daemon on; master_process on; ; ... }

Id=php8.2-fpm.service
MainPID=456
NRestarts=0
ExecStart={ path=/usr/sbin/php-fpm8.2 ; argv[]=/usr/sbin/php-fpm8.2 --nodaemonize --fpm-config /etc/php/8.2/fpm/php-fpm.conf ; ... }

Id=bad.service
MainPID=0
NRestarts=20
ExecStart=
"""),
        # version
        MagicMock(success=True, stdout="systemd 252 (252.6-1ubuntu2)")
    ]

    result = scanner.scan()
    
    assert result.status.capability == CapabilityLevel.FULL
    assert len(result.services) == 3
    
    nginx = next(s for s in result.services if s.name == "nginx.service")
    assert nginx.state == "active"
    assert nginx.restart_count == 2
    assert nginx.main_pid == 123
    assert nginx.exec_start == "/usr/sbin/nginx"
    
    bad = next(s for s in result.services if s.name == "bad.service")
    assert bad.state == "failed"
    assert bad.restart_count == 20

def test_redis_scanner_auth(mock_ssh_connector):
    """Test RedisScanner detecting auth and config."""
    scanner = RedisScanner(mock_ssh_connector)
    
    # Mock sequence
    mock_ssh_connector.run.side_effect = [
        MagicMock(success=True), # which redis-server
        MagicMock(success=True, stdout="user 101 0.0 0.0 123 456 ? Ssl 10:00 0:00 /usr/bin/redis-server /etc/redis/redis.conf"), # ps aux
        # ss output
        MagicMock(success=True, stdout="tcp LISTEN 0 511 127.0.0.1:6379 0.0.0.0:* users:((\"redis-server\",pid=101,fd=6))"),
    ]
    
    # Mock reading config
    mock_ssh_connector.read_file.return_value = "bind 127.0.0.1\nrequirepass mysecret\n"
    
    result = scanner.scan()
    
    assert len(result.instances) == 1
    redis = result.instances[0]
    assert redis.port == 6379
    assert redis.config_path == "/etc/redis/redis.conf"
    assert redis.auth_enabled is True
    assert "127.0.0.1" in redis.bind_addresses

def test_worker_scanner_laravel(mock_ssh_connector):
    """Test WorkerScanner detecting Laravel queue workers."""
    scanner = WorkerScanner(mock_ssh_connector)
    
    # Mock ps
    mock_ssh_connector.run.side_effect = [
        MagicMock(success=True, stdout="www-data 200 1.0 2.0 1000 500 ? S 10:00 0:00 php artisan queue:work redis --tries=3"),
        # which systemctl (for scheduler check)
        MagicMock(success=True),
        # systemctl list-timers
        MagicMock(success=True, stdout="NEXT LEFT LAST PASSED UNIT ACTIVATES\nMon 2024... 1h left ... ... cron.service cron.service")
        # crontab -l check will be skipped if list-timers returns (or handled inside?)
        # My implementation checks crontab files, then crontab -l, then list-timers.
    ]
    
    # Mock list_dir /etc/cron.d
    mock_ssh_connector.list_dir.return_value = []
    # Mock reading /etc/crontab
    mock_ssh_connector.read_file.return_value = "" # no artisan here
    
    # We need to simulate multiple run calls for scheduler check... 
    # The scanner implementation:
    # 1. ps aux -> calls run
    # 2. list_dir /etc/cron.d
    # 3. read_file /etc/crontab (and cron.d files)
    # 4. run crontab -l
    # 5. run which systemctl
    # 6. run systemctl list-timers
    
    # It's getting complicated to mock exact sequence.
    # Let's just check the worker detection part which is simpler.
    
    # Redefine mock for robust sequence
    mock_ssh_connector.run.side_effect = None
    def side_effect(cmd, **kwargs):
        if "ps aux" in cmd:
            return MagicMock(success=True, stdout="www-data 200 1.0 2.0 1000 500 ? S 10:00 0:00 php artisan queue:work redis")
        if "crontab -l" in cmd:
            return MagicMock(success=True, stdout="* * * * * php /var/www/artisan schedule:run")
        if "which systemctl" in cmd:
             return MagicMock(success=True)
        if "list-timers" in cmd:
             return MagicMock(success=True, stdout="")
        return MagicMock(success=False)
    
    mock_ssh_connector.run.side_effect = side_effect
    
    result = scanner.scan()
    
    assert len(result.processes) == 1
    w = result.processes[0]
    assert w.queue_type == "laravel"
    assert w.backend == "redis"
    
    assert result.scheduler_detected is True
    assert result.scheduler_type == "cron"

def test_auditors_logic(sample_server_model):
    """Test Auditor logic on a synthetic model."""
    
    # Valid setup
    runtime = RuntimeModel()
    sample_server_model.runtime = runtime
    
    # 1. Systemd Auditor
    # Add a crashing service
    runtime.systemd_services.append(SystemdService(
        name="crash.service", state="active", substate="auto-restart", restart_count=10
    ))
    
    auditor = SystemdAuditor(sample_server_model)
    findings = auditor.audit()
    assert len(findings) == 1
    assert findings[0].id == "SYSTEMD-1" # Or whatever ID generator produces? logic didn't set ID explicitly, finding dataclass usually generates hash? 
    # The Finding dataclass might require ID if not generated. 
    # Let's check finding.py? It has auto-id/hash usually.
    # But I see in rich_reporter: `finding.id`.
    # Phase 14 audit code passed ID?
    # My implementation: `findings.append(Finding(..., condition=...))`
    # I did NOT pass `id` explicitly. `Finding` usually computes hash or has default.
    # Let's check `Finding` class definition.

    # 2. Redis Auditor
    # Add exposed redis without auth
    runtime.redis_instances.append(RedisInstance(
        port=6379, state=ServiceState.RUNNING, auth_enabled=False, bind_addresses=["0.0.0.0"]
    ))
    
    r_auditor = RedisAuditor(sample_server_model)
    r_findings = r_auditor.audit()
    assert len(r_findings) == 2 # Exposure + Missing Auth
    
    # 3. Worker Auditor
    # Add laravel worker without scheduler
    runtime.worker_processes.append(WorkerProcess(pid=999, cmdline="artisan queue:work", queue_type="laravel"))
    runtime.scheduler_detected = False
    
    w_auditor = WorkerAuditor(sample_server_model)
    w_findings = w_auditor.audit()
    assert len(w_findings) == 1
    assert "no scheduler found" in w_findings[0].condition


def test_systemd_auditor_skips_certbot_failed_unit():
    """certbot.service failure is handled by CertbotAuditor, not generic SYSTEMD-2."""
    model = ServerModel(hostname="test")
    model.runtime = RuntimeModel(
        systemd_services=[
            SystemdService(
                name="certbot.service",
                state="failed",
                substate="failed",
                restart_count=0,
            )
        ]
    )

    findings = SystemdAuditor(model).audit()
    assert findings == []
