"""Redis Auditor - Audits Redis instances for security risks.

Identifies public exposure and missing authentication.
"""

from server_doctor.model.evidence import Evidence, Severity
from server_doctor.model.finding import Finding
from server_doctor.model.server import ServerModel


class RedisAuditor:
    """Auditor for Redis security."""

    def __init__(self, model: ServerModel) -> None:
        self.model = model

    def audit(self) -> list[Finding]:
        """Run all Redis security checks."""
        findings: list[Finding] = []
        
        if not hasattr(self.model, "runtime") or not self.model.runtime.redis_instances:
            return findings

        findings.extend(self._check_public_exposure())
        findings.extend(self._check_missing_auth())
        
        return findings

    def _check_public_exposure(self) -> list[Finding]:
        """Check for Redis exposed on 0.0.0.0 (REDIS-1)."""
        findings: list[Finding] = []
        
        for redis in self.model.runtime.redis_instances:
            exposed = False
            listening_ip = "unknown"
            
            # Check bind addresses
            for addr in redis.bind_addresses:
                if addr == "0.0.0.0" or addr == "::":
                    exposed = True
                    listening_ip = addr
                    break
            
            if exposed:
                # Severity depends on auth
                severity = Severity.CRITICAL
                if redis.auth_enabled is True:
                     severity = Severity.WARNING
                
                findings.append(Finding(
                    id="REDIS-1",
                    severity=severity,
                    confidence=1.0,
                    condition=f"Redis exposed on public interface ({listening_ip}:{redis.port})",
                    cause=f"Redis is bound to {listening_ip} without firewall/VPC protection context verified.",
                    evidence=[Evidence(
                        source_file="ss",
                        line_number=1,
                        excerpt=f"Listen: {listening_ip}:{redis.port}",
                        command=f"ss -lntp | grep :{redis.port}"
                    )],
                    treatment="Bind Redis to 127.0.0.1 in redis.conf: 'bind 127.0.0.1'.",
                    impact=["Data breach risk", "Unauthorized command execution", "DoS attacks"]
                ))
                
        return findings

    def _check_missing_auth(self) -> list[Finding]:
        """Check for missing authentication (REDIS-2)."""
        findings: list[Finding] = []
        
        for redis in self.model.runtime.redis_instances:
            if redis.auth_enabled is False:
                # Explicitly disabled
                findings.append(Finding(
                    id="REDIS-2",
                    severity=Severity.CRITICAL,
                    confidence=1.0,
                    condition=f"Redis authentication is disabled on port {redis.port}",
                    cause=f"No 'requirepass' or ACL configuration found in {redis.config_path}",
                    evidence=[Evidence(
                        source_file=redis.config_path or "redis.conf",
                        line_number=1,
                        excerpt="requirepass <missing>",
                        command=f"cat {redis.config_path}" if redis.config_path else "check config"
                    )],
                    treatment="Enable authentication: set 'requirepass <strong_password>' in redis.conf.",
                    impact=["Unauthorized data access", "Configuration manipulation"]
                ))
            elif redis.auth_enabled is None:
                # Unknown (config unreadable)
                findings.append(Finding(
                    id="REDIS-3",
                    severity=Severity.INFO,
                    confidence=0.5,
                    condition=f"Redis authentication status unknown on port {redis.port}",
                    cause=f"Could not read config file at {redis.config_path}",
                    evidence=[Evidence(
                        source_file="redis.conf",
                        line_number=1,
                        excerpt="Config unreadable",
                        command=f"ls -l {redis.config_path}" if redis.config_path else ""
                    )],
                    treatment="Verify Redis configuration permissions.",
                    impact=["Potential security blindspot"]
                ))
                
        return findings
