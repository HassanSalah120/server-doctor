"""Read-only PHP-FPM deep scanner."""

from __future__ import annotations

import re

from server_doctor.model.server import PhpFpmDeepModel


class PhpFpmDeepScanner:
    def __init__(self, ssh) -> None:
        self.ssh = ssh

    def scan(self, sockets: list[str] | None = None) -> PhpFpmDeepModel:
        model = PhpFpmDeepModel(enabled=True)
        for socket in sockets or []:
            result = self.ssh.run(f"test -S {socket}")
            model.socket_exists[socket] = result.exit_code == 0
        model.cli_version = _first_line(self.ssh.run("php -r 'echo PHP_VERSION;'").stdout)
        model.fpm_version = _first_line(
            self.ssh.run("php-fpm -v 2>&1 || php-fpm8.3 -v 2>&1 || true").stdout
        )
        ini = self.ssh.run("php -i 2>/dev/null || true").stdout
        model.opcache_enabled = _ini_bool(ini, "opcache.enable")
        model.slowlog_enabled = "slowlog => no value" not in ini.lower()
        model.memory_limit_mb = _size_mb(_ini_value(ini, "memory_limit"))
        model.upload_max_filesize_mb = _size_mb(_ini_value(ini, "upload_max_filesize"))
        model.post_max_size_mb = _size_mb(_ini_value(ini, "post_max_size"))
        disabled = _ini_value(ini, "disable_functions") or ""
        model.dangerous_functions_disabled = "exec" in disabled or "shell_exec" in disabled
        return model


def _first_line(value: str) -> str | None:
    line = (value or "").strip().splitlines()
    return line[0].strip() if line else None


def _ini_value(text: str, key: str) -> str | None:
    match = re.search(rf"^{re.escape(key)}\s*=>\s*([^=]+?)\s*=>", text, re.I | re.M)
    return match.group(1).strip() if match else None


def _ini_bool(text: str, key: str) -> bool | None:
    value = (_ini_value(text, key) or "").lower()
    if value in {"on", "1", "true", "yes"}:
        return True
    if value in {"off", "0", "false", "no"}:
        return False
    return None


def _size_mb(value: str | None) -> int | None:
    if not value:
        return None
    value = value.strip().lower()
    if value == "-1":
        return None
    try:
        number = int(re.match(r"\d+", value).group(0))
    except Exception:
        return None
    if value.endswith("g"):
        return number * 1024
    if value.endswith("k"):
        return max(1, number // 1024)
    return number
