"""Logs Scanner - Collects recent runtime error signals from logs/journal."""

from __future__ import annotations

import os
import re

from server_doctor.connector.ssh import CommandResult, SSHConnector
from server_doctor.model.server import LogsModel


class LogsScanner:
    """Collect lightweight log-derived health signals."""

    _NGINX_PATTERNS: dict[str, re.Pattern[str]] = {
        "upstream_timeout": re.compile(r"upstream timed out", re.IGNORECASE),
        "upstream_connect_failed": re.compile(r"connect\(\)\s+failed", re.IGNORECASE),
        "bad_gateway": re.compile(r"\b502\b|bad gateway", re.IGNORECASE),
        "gateway_timeout": re.compile(r"\b504\b|gateway timeout", re.IGNORECASE),
        "ssl_error": re.compile(r"(ssl|tls).*(error|failed|alert)", re.IGNORECASE),
    }

    _PHP_FPM_PATTERNS: dict[str, re.Pattern[str]] = {
        "max_children_reached": re.compile(r"pm\.max_children|server reached max_children", re.IGNORECASE),
        "slow_requests": re.compile(r"slow request|slowlog|request_slowlog_timeout", re.IGNORECASE),
        "child_exited": re.compile(r"child .* exited", re.IGNORECASE),
        "pool_busy": re.compile(r"seems busy", re.IGNORECASE),
    }

    def __init__(self, ssh: SSHConnector) -> None:
        self.ssh = ssh
        self._journal_max_lines = self._env_int("server_doctor_LOG_JOURNAL_MAX_LINES", 2000, min_value=200, max_value=12000)
        self._nginx_tail_lines = self._env_int("server_doctor_LOG_NGINX_TAIL_LINES", 400, min_value=80, max_value=2000)
        self._php_tail_lines = self._env_int("server_doctor_LOG_PHP_TAIL_LINES", 250, min_value=80, max_value=2000)
        self._docker_tail_lines = self._env_int("server_doctor_LOG_DOCKER_TAIL_LINES", 60, min_value=20, max_value=400)

    def scan(self) -> LogsModel:
        model = LogsModel()
        self._collect_journal(model)
        self._collect_nginx_log_signals(model)
        self._collect_php_fpm_log_signals(model)
        self._collect_docker_log_signals(model)
        return model

    def _env_int(self, name: str, default: int, min_value: int = 0, max_value: int = 1_000_000) -> int:
        raw = os.getenv(name, str(default)).strip()
        try:
            value = int(raw)
        except ValueError:
            value = default
        return max(min_value, min(max_value, value))

    def _classify_result(
        self,
        result: CommandResult,
        *,
        empty_status: str = "not_observed",
        missing_status: str = "unavailable",
    ) -> tuple[str, str]:
        if result.success:
            out = (result.stdout or "").strip()
            return ("collected", "") if out else (empty_status, "")

        stderr = (result.stderr or "").strip().lower()
        if any(token in stderr for token in ("permission denied", "operation not permitted", "not in the sudoers", "sudo authentication failed")):
            return ("insufficient_permissions", stderr[:220])
        if any(token in stderr for token in ("command not found", "not found", "no such file", "no such command")):
            return (missing_status, stderr[:220])
        if any(
            token in stderr
            for token in (
                "ssh execution error",
                "channelexception",
                "connect failed",
                "no existing session",
                "socket is closed",
                "connection reset",
            )
        ):
            return ("not_accessible", stderr[:220])
        if "timed out" in stderr or "timeout" in stderr:
            return ("timeout", stderr[:220])
        return ("error", stderr[:220] or f"exit_code={result.exit_code}")

    def _run_stdout(
        self,
        command: str,
        *,
        timeout: float = 8,
        use_sudo: bool = True,
        empty_status: str = "not_observed",
        missing_status: str = "unavailable",
    ) -> tuple[str, str, str]:
        result = self.ssh.run(command, timeout=timeout, use_sudo=use_sudo)
        status, note = self._classify_result(
            result,
            empty_status=empty_status,
            missing_status=missing_status,
        )
        if not result.success:
            return ("", status, note)
        return ((result.stdout or "").strip(), status, note)

    def _record(self, model: LogsModel, key: str, status: str, note: str = "") -> None:
        model.collection_status[key] = status
        if note:
            model.collection_notes[key] = note[:220]

    def _to_int(self, text: str) -> int | None:
        clean = text.strip()
        if clean.isdigit():
            return int(clean)
        return None

    def _collect_journal(self, model: LogsModel) -> None:
        _, check_status, check_note = self._run_stdout(
            "command -v journalctl 2>/dev/null",
            timeout=3,
            use_sudo=False,
            empty_status="not_supported",
            missing_status="not_supported",
        )
        if check_status != "collected":
            note = check_note or "journalctl binary not available"
            self._record(model, "journal.errors_24h", check_status, note)
            self._record(model, "journal.oom_24h", check_status, note)
            return

        output, status, note = self._run_stdout(
            "sh -lc '"
            f"errors=$(journalctl -p err..alert --since \"24 hours ago\" --no-pager 2>/dev/null | head -n {self._journal_max_lines} | wc -l); "
            f"oom=$(journalctl --since \"24 hours ago\" --no-pager 2>/dev/null | head -n {self._journal_max_lines} "
            "| grep -Ei \"out of memory|oom-kill|killed process\" | wc -l); "
            "printf \"errors=%s\\noom=%s\\n\" \"$errors\" \"$oom\"'",
            timeout=10,
            empty_status="not_observed",
        )
        self._record(model, "journal.errors_24h", status, note)
        self._record(model, "journal.oom_24h", status, note)
        if not output:
            return

        parsed: dict[str, str] = {}
        for raw in output.splitlines():
            line = raw.strip()
            if "=" not in line:
                continue
            key, value = line.split("=", 1)
            parsed[key.strip()] = value.strip()

        model.journal_errors_24h = self._to_int(parsed.get("errors", ""))
        model.journal_oom_events_24h = self._to_int(parsed.get("oom", ""))

    def _collect_nginx_log_signals(self, model: LogsModel) -> None:
        output, status, note = self._run_stdout(
            "for f in /var/log/nginx/error.log /usr/local/nginx/logs/error.log; "
            f"do [ -f \"$f\" ] && tail -n {self._nginx_tail_lines} \"$f\"; done 2>/dev/null; true",
            timeout=10,
            empty_status="not_observed",
        )
        self._record(model, "nginx.error_log", status, note)
        if not output:
            return

        counts = {key: 0 for key in self._NGINX_PATTERNS}
        samples: list[str] = []
        for raw in output.splitlines():
            line = raw.strip()
            if not line:
                continue
            matched = False
            for key, pattern in self._NGINX_PATTERNS.items():
                if pattern.search(line):
                    counts[key] += 1
                    matched = True
            if matched and len(samples) < 12:
                samples.append(line[:220])

        model.nginx_error_counts = {k: v for k, v in counts.items() if v > 0}
        model.nginx_error_samples = samples

    def _collect_php_fpm_log_signals(self, model: LogsModel) -> None:
        output, status, note = self._run_stdout(
            "for f in /var/log/php*-fpm.log /var/log/php*-fpm/*.log /var/log/php-fpm.log /var/log/php-fpm/*.log; "
            f"do [ -f \"$f\" ] && tail -n {self._php_tail_lines} \"$f\"; done 2>/dev/null; true",
            timeout=10,
            empty_status="not_observed",
        )
        self._record(model, "php_fpm.logs", status, note)
        if not output:
            return

        counts = {key: 0 for key in self._PHP_FPM_PATTERNS}
        samples: list[str] = []
        for raw in output.splitlines():
            line = raw.strip()
            if not line:
                continue
            matched = False
            for key, pattern in self._PHP_FPM_PATTERNS.items():
                if pattern.search(line):
                    counts[key] += 1
                    matched = True
            if matched and len(samples) < 12:
                samples.append(line[:220])

        model.php_fpm_error_counts = {k: v for k, v in counts.items() if v > 0}
        model.php_fpm_error_samples = samples

    def _collect_docker_log_signals(self, model: LogsModel) -> None:
        _, check_status, check_note = self._run_stdout(
            "command -v docker 2>/dev/null",
            timeout=3,
            empty_status="not_supported",
            missing_status="not_supported",
        )
        if check_status != "collected":
            note = check_note or "docker binary not available"
            self._record(model, "docker.ps", check_status, note)
            self._record(model, "docker.logs", check_status, note)
            return

        ps_output, status, note = self._run_stdout(
            "docker ps -a --format '{{.Names}}|{{.Status}}' 2>/dev/null",
            timeout=8,
            empty_status="not_observed",
        )
        self._record(model, "docker.ps", status, note)
        if not ps_output:
            return

        crashloops: list[str] = []
        for raw in ps_output.splitlines():
            line = raw.strip()
            if not line or "|" not in line:
                continue
            name, status = line.split("|", 1)
            status_l = status.lower()
            if "restarting" in status_l:
                crashloops.append(name.strip())
                continue
            if "exited" in status_l and "second" in status_l:
                crashloops.append(name.strip())

        model.docker_crashloop_containers = sorted(set(c for c in crashloops if c))
        if not model.docker_crashloop_containers:
            self._record(model, "docker.logs", "not_observed")
            return

        samples: list[str] = []
        for container in model.docker_crashloop_containers[:3]:
            logs, log_status, log_note = self._run_stdout(
                f"docker logs --tail {self._docker_tail_lines} {container} 2>&1",
                timeout=8,
                empty_status="not_observed",
            )
            if log_status != "collected":
                self._record(model, f"docker.logs.{container}", log_status, log_note)
            if not logs:
                continue
            self._record(model, f"docker.logs.{container}", "collected")
            for raw in logs.splitlines():
                line = raw.strip()
                if not line:
                    continue
                line_l = line.lower()
                if any(token in line_l for token in ("error", "exception", "fatal", "panic", "traceback")):
                    samples.append(f"{container}: {line[:190]}")
                    if len(samples) >= 20:
                        break
            if len(samples) >= 20:
                break

        model.docker_error_samples = samples
        self._record(model, "docker.logs", "collected" if samples else "not_observed")
