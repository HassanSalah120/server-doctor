"""PHP-FPM Auditor.

Checks for PHP-FPM pool configuration.
Typically located in /etc/php/*/fpm/pool.d/www.conf.

Checks:
- PHPFPM-1: Slowlog disabled
- PHPFPM-2: pm.max_children default/low
- PHPFPM-3: Socket user/group mismatch (advanced - placeholder)
"""

import re
from dataclasses import dataclass
from typing import TYPE_CHECKING

from server_doctor.checks import BaseCheck, CheckContext, register_check
from server_doctor.model.evidence import Evidence, Severity
from server_doctor.model.finding import Finding

if TYPE_CHECKING:
    from server_doctor.connector.ssh import SSHConnector


@register_check
class PHPFPMAuditor(BaseCheck):
    """Auditor for PHP-FPM settings."""
    
    @property
    def category(self) -> str:
        return "phpfpm"
    
    @property
    def requires_ssh(self) -> bool:
        return True
    
    def run(self, context: CheckContext) -> list[Finding]:
        """Run PHP-FPM checks."""
        if not context.ssh:
            return []
            
        findings: list[Finding] = []
        
        # 1. Locate PHP-FPM pool configs
        # Find active PHP version first or just grep all?
        cmd = "find /etc/php -name www.conf 2>/dev/null"
        result = context.ssh.run(cmd)
        
        config_files = [f for f in result.stdout.strip().split("\n") if f.strip()]
        
        for config_path in config_files:
            findings.extend(self._check_pool_config(context.ssh, config_path))
            
        return findings

    def _check_pool_config(self, ssh: "SSHConnector", config_path: str) -> list[Finding]:
        """Analyze a single FPM pool config."""
        findings = []
        
        # Read content
        content_res = ssh.run(f"cat {config_path}")
        content = content_res.stdout
        
        # Remove comments (; usually)
        active_lines = []
        for line in content.split("\n"):
            clean = line.strip()
            if clean and not clean.startswith(";"):
                active_lines.append(clean)
        
        clean_content = "\n".join(active_lines)
        
        # PHPFPM-1: Slowlog check
        has_slowlog = "slowlog =" in clean_content or "slowlog=" in clean_content
        request_slowlog_timeout = "request_slowlog_timeout =" in clean_content or "request_slowlog_timeout=" in clean_content
        
        if not (has_slowlog and request_slowlog_timeout):
            findings.append(Finding(
                id="PHPFPM-1",
                severity=Severity.INFO,
                confidence=0.9,
                condition=f"PHP-FPM slowlog disabled in {config_path}",
                cause="Missing 'slowlog' or 'request_slowlog_timeout' directive.",
                evidence=[Evidence(
                    source_file=config_path,
                    line_number=0,
                    excerpt="slowlog settings missing",
                    command=f"cat {config_path}",
                )],
                treatment=(
                    f"Enable slowlog in {config_path}:\n"
                    "    slowlog = /var/log/php-fpm/www-slow.log\n"
                    "    request_slowlog_timeout = 5s"
                ),
                impact=["Cannot debug slow PHP requests"],
            ))
            
        # PHPFPM-2: pm.max_children check
        # Look for: pm.max_children = 5
        max_children_match = re.search(r"pm\.max_children\s*=\s*(\d+)", clean_content)
        if max_children_match:
            val = int(max_children_match.group(1))
            if val <= 5:
                 findings.append(Finding(
                    id="PHPFPM-2",
                    severity=Severity.WARNING,
                    confidence=0.8,
                    condition=f"Low pm.max_children in {config_path}: {val}",
                    cause="Default setting (5) is often too low for modern servers.",
                    evidence=[Evidence(
                        source_file=config_path,
                        line_number=0,
                        excerpt=f"pm.max_children = {val}",
                        command="",
                    )],
                    treatment=(
                        "Increase pm.max_children based on available RAM.\n"
                        "Use established calculator (Total RAM - Reserved) / Process Size."
                    ),
                    impact=["High traffic will cause 502 errors"],
                ))
        
        return findings
