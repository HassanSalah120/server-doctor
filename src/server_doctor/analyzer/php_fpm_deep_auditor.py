"""Deep PHP-FPM runtime/config auditor."""

from __future__ import annotations

from server_doctor.model.evidence import Evidence, Severity
from server_doctor.model.finding import Finding
from server_doctor.model.server import ServerBlock, ServerModel


class PhpFpmDeepAuditor:
    def __init__(self, model: ServerModel) -> None:
        self.model = model

    def audit(self) -> list[Finding]:
        findings: list[Finding] = []
        for server in self.model.nginx.servers if self.model.nginx else []:
            for socket_path in _fastcgi_unix_sockets(server):
                exists = self.model.php_fpm_deep.socket_exists.get(socket_path)
                if exists is False:
                    findings.append(socket_missing_finding(socket_path, server))
                accessible = self.model.php_fpm_deep.socket_accessible.get(socket_path)
                if accessible is False:
                    findings.append(_finding(
                        "PHPFPM-DEEP-002",
                        Severity.CRITICAL,
                        "Nginx cannot access PHP-FPM socket",
                        f"Socket {socket_path} exists but is not accessible to Nginx.",
                        server,
                        f"fastcgi_pass unix:{socket_path}",
                    ))
        for service, state in self.model.php_fpm_deep.service_states.items():
            if state in {"failed", "inactive", "stopped"}:
                findings.append(_generic(
                    "PHPFPM-DEEP-003",
                    Severity.CRITICAL,
                    "PHP-FPM service is not healthy",
                    f"{service} is {state}.",
                    f"systemctl is-active {service}",
                ))
        if _version_mismatch(
            self.model.php_fpm_deep.cli_version,
            self.model.php_fpm_deep.fpm_version,
        ):
            findings.append(_generic(
                "PHPFPM-DEEP-006",
                Severity.WARNING,
                "PHP CLI and FPM versions differ",
                "CLI PHP and PHP-FPM appear to report different versions.",
                "php -v && php-fpm -v",
            ))
        if self.model.php_fpm_deep.opcache_enabled is False:
            findings.append(_generic(
                "PHPFPM-DEEP-007",
                Severity.WARNING,
                "Opcache is disabled",
                "PHP opcache.enable is off.",
                "php -i | grep opcache.enable",
            ))
        if (
            self.model.php_fpm_deep.memory_limit_mb is not None
            and self.model.php_fpm_deep.memory_limit_mb < 128
        ):
            findings.append(_generic(
                "PHPFPM-DEEP-011",
                Severity.WARNING,
                "PHP memory_limit is low for Laravel",
                f"memory_limit={self.model.php_fpm_deep.memory_limit_mb}M.",
                "php -i | grep memory_limit",
            ))
        return findings


def socket_missing_finding(socket_path: str, server: ServerBlock) -> Finding:
    return Finding(
        id="PHPFPM-DEEP-001",
        severity=Severity.CRITICAL,
        confidence=0.95,
        condition="Nginx points to missing PHP-FPM socket",
        cause=f"fastcgi_pass references {socket_path}, but the socket was not found.",
        evidence=[
            Evidence(
                source_file=server.source_file or "nginx config",
                line_number=server.line_number,
                excerpt=f"fastcgi_pass unix:{socket_path}",
                command=f"test -S {socket_path}",
            )
        ],
        treatment="Start the correct PHP-FPM service or update fastcgi_pass.",
        impact=["PHP requests may return 502 Bad Gateway."],
    )


def _fastcgi_unix_sockets(server: ServerBlock) -> list[str]:
    sockets: list[str] = []
    for location in server.locations:
        target = location.fastcgi_pass or ""
        if target.startswith("unix:"):
            sockets.append(target.removeprefix("unix:").split(";", 1)[0])
    return sockets


def _finding(rule_id, severity, condition, cause, server, excerpt) -> Finding:
    return Finding(
        id=rule_id,
        severity=severity,
        confidence=0.9,
        condition=condition,
        cause=cause,
        evidence=[Evidence(server.source_file or "nginx config", server.line_number, excerpt)],
        treatment="Review PHP-FPM pool/socket ownership and Nginx fastcgi_pass.",
        impact=["PHP requests may fail."],
    )


def _generic(rule_id, severity, condition, cause, command) -> Finding:
    return Finding(
        id=rule_id,
        severity=severity,
        confidence=0.8,
        condition=condition,
        cause=cause,
        evidence=[Evidence("php-fpm scan", 0, cause, command)],
        treatment="Review PHP-FPM configuration and service status.",
        impact=["Application runtime reliability may be reduced."],
    )


def _version_mismatch(cli: str | None, fpm: str | None) -> bool:
    if not cli or not fpm:
        return False
    return cli.split()[0].split(".")[:2] != fpm.split()[0].split(".")[:2]
