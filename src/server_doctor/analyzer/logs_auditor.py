"""Logs Auditor - Derive actionable findings from recent log signals."""

from __future__ import annotations

from server_doctor.engine.runtime_thresholds import env_int
from server_doctor.model.evidence import Evidence, Severity
from server_doctor.model.finding import Finding
from server_doctor.model.server import ServerModel


class LogsAuditor:
    """Auditor for journal/nginx/php-fpm/docker error signals."""

    def __init__(self, model: ServerModel) -> None:
        self.model = model
        self._journal_warn = env_int("server_doctor_LOG_JOURNAL_WARN_COUNT", 120, min_value=10, max_value=5000)
        self._journal_crit = env_int("server_doctor_LOG_JOURNAL_CRIT_COUNT", 500, min_value=self._journal_warn + 1, max_value=20000)
        self._oom_crit = env_int("server_doctor_OOM_CRIT_COUNT", 3, min_value=1, max_value=200)
        self._nginx_warn = env_int("server_doctor_LOG_NGINX_UPSTREAM_WARN_COUNT", 5, min_value=1, max_value=2000)
        self._nginx_crit = env_int("server_doctor_LOG_NGINX_UPSTREAM_CRIT_COUNT", 20, min_value=self._nginx_warn + 1, max_value=5000)
        self._php_slow_warn = env_int("server_doctor_LOG_PHP_SLOW_WARN_COUNT", 20, min_value=1, max_value=5000)
        self._docker_crashloop_crit = env_int("server_doctor_LOG_DOCKER_CRASHLOOP_CRIT_COUNT", 3, min_value=1, max_value=100)

    def audit(self) -> list[Finding]:
        if not hasattr(self.model, "logs"):
            return []

        findings: list[Finding] = []
        findings.extend(self._check_journal_error_volume())
        findings.extend(self._check_oom_events())
        findings.extend(self._check_nginx_upstream_errors())
        findings.extend(self._check_php_fpm_pressure())
        findings.extend(self._check_docker_crashloops())
        return findings

    def _check_journal_error_volume(self) -> list[Finding]:
        count = self.model.logs.journal_errors_24h
        if count is None or count < self._journal_warn:
            return []

        severity = Severity.CRITICAL if count >= self._journal_crit else Severity.WARNING
        return [
            Finding(
                id="LOG-1",
                severity=severity,
                confidence=0.78,
                condition=f"High system error log volume in last 24h ({count} entries)",
                cause="`journalctl -p err..alert` indicates elevated host-level error activity.",
                evidence=[
                    Evidence(
                        source_file="journalctl",
                        line_number=1,
                        excerpt=f"errors_24h={count}",
                        command="journalctl -p err..alert --since '24 hours ago' --no-pager | wc -l",
                    )
                ],
                treatment="Review top recurring errors and correlate with service incidents before they cascade.",
                impact=[
                    "Increased risk of latent incidents going unnoticed",
                    "Operational noise can hide critical failures",
                ],
            )
        ]

    def _check_oom_events(self) -> list[Finding]:
        count = self.model.logs.journal_oom_events_24h
        if count is None or count <= 0:
            return []

        severity = Severity.CRITICAL if count >= self._oom_crit else Severity.WARNING
        return [
            Finding(
                id="LOG-2",
                severity=severity,
                confidence=0.88,
                condition=f"OOM incidents from log scanner: {count} event(s) in last 24h",
                cause=f"Log scanner detected {count} OOM kill entries in system journal.",
                evidence=[
                    Evidence(
                        source_file="journalctl",
                        line_number=1,
                        excerpt=f"OOM (log scanner): {count} events in 24h",
                        command="journalctl --since '24 hours ago' | egrep -i 'out of memory|oom-kill|killed process'",
                    )
                ],
                treatment="Reduce memory pressure, right-size limits, and inspect processes repeatedly killed by OOM.",
                impact=[
                    "Service instability and unexpected process termination",
                    "Higher request failure and timeout rates",
                ],
            )
        ]

    def _check_nginx_upstream_errors(self) -> list[Finding]:
        counts = self.model.logs.nginx_error_counts or {}
        if not counts:
            return []

        upstream_total = (
            int(counts.get("upstream_timeout", 0))
            + int(counts.get("upstream_connect_failed", 0))
            + int(counts.get("gateway_timeout", 0))
            + int(counts.get("bad_gateway", 0))
        )
        if upstream_total < self._nginx_warn:
            return []

        severity = Severity.CRITICAL if upstream_total >= self._nginx_crit else Severity.WARNING
        sample = self.model.logs.nginx_error_samples[:5]
        excerpt = sample[0] if sample else (
            f"upstream_timeout={counts.get('upstream_timeout', 0)}, "
            f"connect_failed={counts.get('upstream_connect_failed', 0)}, "
            f"gateway_timeout={counts.get('gateway_timeout', 0)}, bad_gateway={counts.get('bad_gateway', 0)}"
        )
        return [
            Finding(
                id="LOG-NGX-1",
                severity=severity,
                confidence=0.84,
                condition=f"Frequent Nginx upstream/backend errors detected ({upstream_total} matches)",
                cause=(
                    "Nginx error logs show repeated upstream timeout/connect failures or 502/504 patterns."
                ),
                evidence=[
                    Evidence(
                        source_file="/var/log/nginx/error.log",
                        line_number=1,
                        excerpt=excerpt[:220],
                        command="tail -n 400 /var/log/nginx/error.log",
                    )
                ],
                treatment="Validate backend health/capacity and upstream timeouts; investigate slow dependencies.",
                impact=[
                    "User-visible 502/504 response spikes",
                    "Request reliability degradation under load",
                ],
            )
        ]

    def _check_php_fpm_pressure(self) -> list[Finding]:
        counts = self.model.logs.php_fpm_error_counts or {}
        max_children = int(counts.get("max_children_reached", 0))
        slow = int(counts.get("slow_requests", 0))
        if max_children <= 0 and slow < self._php_slow_warn:
            return []

        severity = Severity.WARNING if max_children > 0 else Severity.INFO
        sample = self.model.logs.php_fpm_error_samples[:4]
        excerpt = sample[0] if sample else f"max_children={max_children}, slow_requests={slow}"
        return [
            Finding(
                id="LOG-PHP-1",
                severity=severity,
                confidence=0.8,
                condition="PHP-FPM pressure patterns detected in logs",
                cause=(
                    "PHP-FPM log patterns indicate worker saturation and/or slow request handling."
                ),
                evidence=[
                    Evidence(
                        source_file="/var/log/php-fpm.log",
                        line_number=1,
                        excerpt=excerpt[:220],
                        command="tail -n 250 /var/log/php*-fpm*.log",
                    )
                ],
                treatment="Tune FPM pool sizes and investigate slow endpoints causing worker exhaustion.",
                impact=[
                    "Intermittent upstream timeouts and elevated request latency",
                ],
            )
        ]

    def _check_docker_crashloops(self) -> list[Finding]:
        crashloops = self.model.logs.docker_crashloop_containers or []
        if not crashloops:
            return []

        severity = Severity.CRITICAL if len(crashloops) >= self._docker_crashloop_crit else Severity.WARNING
        sample = self.model.logs.docker_error_samples[:4]
        excerpt = sample[0] if sample else ", ".join(crashloops[:4])
        return [
            Finding(
                id="LOG-DOCKER-1",
                severity=severity,
                confidence=0.82,
                condition=f"Container restart/crash-loop signals detected ({len(crashloops)} container(s))",
                cause="Docker status/logs indicate repeated restart patterns for one or more containers.",
                evidence=[
                    Evidence(
                        source_file="docker",
                        line_number=1,
                        excerpt=excerpt[:220],
                        command="docker ps -a --format '{{.Names}}|{{.Status}}'; docker logs --tail 60 <container>",
                    )
                ],
                treatment="Inspect failing containers, fix startup errors, and add readiness/liveness safeguards.",
                impact=[
                    "Service instability and reduced availability",
                ],
            )
        ]
