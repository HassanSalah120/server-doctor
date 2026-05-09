"""Laravel Readiness Auditor.

Checks for common Laravel misconfigurations and missing components.
NEVER outputs .env values - only existence/flag detection.

Checks:
- LARAVEL-1: APP_DEBUG=true (Critical - always)
- LARAVEL-2: storage/ not writable by web user
- LARAVEL-3: bootstrap/cache not writable  
- LARAVEL-4: Scheduler cron not detected
- LARAVEL-5: Queue worker not detected
"""

import re
from dataclasses import dataclass
from typing import TYPE_CHECKING

from server_doctor.checks import BaseCheck, CheckContext, register_check
from server_doctor.model.evidence import Evidence, Severity
from server_doctor.model.finding import Finding

if TYPE_CHECKING:
    from server_doctor.connector.ssh import SSHConnector


@dataclass
class LaravelProject:
    """Detected Laravel project."""
    path: str
    has_artisan: bool = False
    has_env: bool = False
    app_debug: bool | None = None  # True/False/None(unknown)
    app_env: str | None = None
    storage_writable: bool | None = None
    bootstrap_cache_writable: bool | None = None


@register_check
class LaravelAuditor(BaseCheck):
    """Auditor for Laravel readiness checks."""
    
    @property
    def category(self) -> str:
        return "laravel"
    
    @property
    def requires_ssh(self) -> bool:
        return True
    
    def run(self, context: CheckContext) -> list[Finding]:
        """Run Laravel audits on all detected projects."""
        if not context.ssh:
            return []
        
        findings: list[Finding] = []
        projects = self._discover_laravel_projects(context)
        
        for project in projects:
            findings.extend(self._check_app_debug(project))
            findings.extend(self._check_storage_permissions(project))
            findings.extend(self._check_bootstrap_cache(project))
        
        # Global checks (not per-project)
        findings.extend(self._check_scheduler_cron(context))
        findings.extend(self._check_queue_worker(context))
        
        return findings
    
    def _discover_laravel_projects(self, context: CheckContext) -> list[LaravelProject]:
        """Find all Laravel projects from the model."""
        projects: list[LaravelProject] = []
        
        if not context.model.projects:
            return projects
        
        for proj_info in context.model.projects:
            if proj_info.type and proj_info.type.value == "laravel":
                lp = LaravelProject(path=proj_info.path)
                
                # Check artisan exists
                result = context.ssh.run(f"test -f {proj_info.path}/artisan && echo yes || echo no")
                lp.has_artisan = result.stdout.strip() == "yes"
                
                # Check .env exists
                result = context.ssh.run(f"test -f {proj_info.path}/.env && echo yes || echo no")
                lp.has_env = result.stdout.strip() == "yes"
                
                if lp.has_env:
                    # Extract DEBUG and ENV flags (not values!)
                    result = context.ssh.run(
                        f"grep -E '^APP_DEBUG=' {proj_info.path}/.env 2>/dev/null | head -1"
                    )
                    if result.stdout.strip():
                        debug_line = result.stdout.strip()
                        lp.app_debug = "true" in debug_line.lower()
                    
                    result = context.ssh.run(
                        f"grep -E '^APP_ENV=' {proj_info.path}/.env 2>/dev/null | head -1"
                    )
                    if result.stdout.strip():
                        env_line = result.stdout.strip()
                        # Extract only the value type, not secrets
                        if "production" in env_line.lower():
                            lp.app_env = "production"
                        elif "local" in env_line.lower():
                            lp.app_env = "local"
                        else:
                            lp.app_env = "other"
                
                # Check storage writable
                result = context.ssh.run(
                    f"test -w {proj_info.path}/storage && echo yes || echo no"
                )
                lp.storage_writable = result.stdout.strip() == "yes"
                
                # Check bootstrap/cache writable
                result = context.ssh.run(
                    f"test -w {proj_info.path}/bootstrap/cache && echo yes || echo no"
                )
                lp.bootstrap_cache_writable = result.stdout.strip() == "yes"
                
                projects.append(lp)
        
        return projects
    
    def _check_app_debug(self, project: LaravelProject) -> list[Finding]:
        """LARAVEL-1: APP_DEBUG=true in production."""
        findings = []
        
        if project.app_debug is True:
            # Critical regardless of environment (safe default)
            findings.append(Finding(
                id="LARAVEL-1",
                severity=Severity.CRITICAL,
                confidence=0.95,
                condition="APP_DEBUG is enabled",
                cause=(
                    f"Laravel project at {project.path} has APP_DEBUG=true. "
                    "This exposes sensitive stack traces and configuration details."
                ),
                evidence=[Evidence(
                    source_file=f"{project.path}/.env",
                    line_number=0,
                    excerpt="APP_DEBUG=true",
                    command="grep APP_DEBUG .env",
                )],
                treatment=(
                    "Set APP_DEBUG=false in production:\n"
                    f"    sed -i 's/APP_DEBUG=true/APP_DEBUG=false/' {project.path}/.env"
                ),
                impact=[
                    "Exposes full stack traces to attackers",
                    "Reveals database credentials and API keys in error pages",
                    "Major security vulnerability",
                ],
            ))
        
        return findings
    
    def _check_storage_permissions(self, project: LaravelProject) -> list[Finding]:
        """LARAVEL-2: storage/ not writable."""
        findings = []
        
        if project.storage_writable is False:
            findings.append(Finding(
                id="LARAVEL-2",
                severity=Severity.WARNING,
                confidence=0.85,
                condition="Laravel storage/ not writable",
                cause=(
                    f"The storage directory at {project.path}/storage is not writable "
                    "by the current user (likely the web server user)."
                ),
                evidence=[Evidence(
                    source_file=f"{project.path}/storage",
                    line_number=0,
                    excerpt="Directory not writable",
                    command="test -w storage",
                )],
                treatment=(
                    "Fix permissions:\n"
                    f"    chown -R www-data:www-data {project.path}/storage\n"
                    f"    chmod -R 775 {project.path}/storage"
                ),
                impact=[
                    "Logs cannot be written",
                    "File uploads will fail",
                    "Cache operations will fail",
                ],
            ))
        
        return findings
    
    def _check_bootstrap_cache(self, project: LaravelProject) -> list[Finding]:
        """LARAVEL-3: bootstrap/cache not writable."""
        findings = []
        
        if project.bootstrap_cache_writable is False:
            findings.append(Finding(
                id="LARAVEL-3",
                severity=Severity.WARNING,
                confidence=0.85,
                condition="Laravel bootstrap/cache not writable",
                cause=(
                    f"The bootstrap/cache directory at {project.path}/bootstrap/cache "
                    "is not writable."
                ),
                evidence=[Evidence(
                    source_file=f"{project.path}/bootstrap/cache",
                    line_number=0,
                    excerpt="Directory not writable",
                    command="test -w bootstrap/cache",
                )],
                treatment=(
                    "Fix permissions:\n"
                    f"    chown -R www-data:www-data {project.path}/bootstrap/cache\n"
                    f"    chmod -R 775 {project.path}/bootstrap/cache"
                ),
                impact=[
                    "Config caching will fail",
                    "Route caching will fail",
                    "Performance optimizations disabled",
                ],
            ))
        
        return findings
    
    def _check_scheduler_cron(self, context: CheckContext) -> list[Finding]:
        """LARAVEL-4: Scheduler cron not detected."""
        findings = []
        
        if not context.ssh:
            return findings
        
        # Check for Laravel scheduler in system cron
        artisan_pattern = "artisan schedule:run"
        
        # Check /etc/crontab
        result = context.ssh.run(
            f"grep -l '{artisan_pattern}' /etc/crontab /etc/cron.d/* 2>/dev/null || echo ''"
        )
        
        # Also check common crontab -l
        crontab_result = context.ssh.run(
            f"crontab -l 2>/dev/null | grep '{artisan_pattern}' || echo ''"
        )
        
        has_scheduler = bool(result.stdout.strip() or crontab_result.stdout.strip())
        
        if not has_scheduler and context.model.projects:
            # Check if any Laravel project exists
            laravel_projects = [
                p for p in context.model.projects 
                if p.type and p.type.value == "laravel"
            ]
            
            if laravel_projects:
                findings.append(Finding(
                    id="LARAVEL-4",
                    severity=Severity.INFO,
                    confidence=0.70,
                    condition="Laravel scheduler cron not detected",
                    cause=(
                        "No cron job found running 'artisan schedule:run'. "
                        "This is needed for scheduled tasks like queue cleanup, email notifications."
                    ),
                    evidence=[Evidence(
                        source_file="/etc/crontab",
                        line_number=0,
                        excerpt="No artisan schedule:run found",
                        command="grep 'artisan schedule:run' /etc/crontab /etc/cron.d/*",
                    )],
                    treatment=(
                        "Add Laravel scheduler to crontab:\n"
                        "    crontab -e\n"
                        "    * * * * * cd /path/to/project && php artisan schedule:run >> /dev/null 2>&1"
                    ),
                    impact=[
                        "Scheduled tasks will not run",
                        "Queue cleanup may not happen",
                        "Emails/notifications may not be sent",
                    ],
                ))
        
        return findings
    
    def _check_queue_worker(self, context: CheckContext) -> list[Finding]:
        """LARAVEL-5: Queue worker not detected."""
        findings = []
        
        if not context.ssh:
            return findings
        
        # Check for queue workers in systemd or supervisor
        checks = [
            # Systemd units
            ("systemctl list-units --type=service 2>/dev/null | grep -E 'horizon|queue|laravel|worker'", "systemd"),
            # Supervisor configs
            ("ls /etc/supervisor/conf.d/*.conf 2>/dev/null | xargs grep -l 'queue:work\\|horizon' 2>/dev/null || echo ''", "supervisor"),
            # Running processes
            ("ps aux 2>/dev/null | grep -E 'queue:work|horizon' | grep -v grep || echo ''", "process"),
        ]
        
        worker_found = False
        for cmd, source in checks:
            result = context.ssh.run(cmd)
            if result.stdout.strip():
                worker_found = True
                break
        
        if not worker_found and context.model.projects:
            laravel_projects = [
                p for p in context.model.projects 
                if p.type and p.type.value == "laravel"
            ]
            
            if laravel_projects:
                findings.append(Finding(
                    id="LARAVEL-5",
                    severity=Severity.INFO,
                    confidence=0.65,
                    condition="Laravel queue worker not detected",
                    cause=(
                        "No active queue worker (artisan queue:work or Horizon) "
                        "detected via systemd, supervisor, or running processes."
                    ),
                    evidence=[Evidence(
                        source_file="/etc/supervisor/conf.d/",
                        line_number=0,
                        excerpt="No queue worker configuration found",
                        command="ps aux | grep queue:work",
                    )],
                    treatment=(
                        "Set up a queue worker with Supervisor:\n"
                        "    apt install supervisor\n"
                        "    # Create /etc/supervisor/conf.d/laravel-worker.conf\n"
                        "    # Or use Laravel Horizon for Redis queues"
                    ),
                    impact=[
                        "Queued jobs will not be processed",
                        "Email notifications delayed indefinitely",
                        "Background tasks will not run",
                    ],
                ))
        
        return findings
