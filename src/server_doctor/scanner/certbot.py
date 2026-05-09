"""Certbot Scanner - Detects real certificate-renewal dependency and risk."""

from __future__ import annotations

import os
from datetime import datetime, timezone

from server_doctor.connector.ssh import SSHConnector
from server_doctor.model.server import CertbotModel, NginxInfo


class CertbotScanner:
    """Collect Certbot runtime and certificate-expiry posture."""

    def __init__(self, ssh: SSHConnector) -> None:
        self.ssh = ssh

    @staticmethod
    def _dry_run_enabled() -> bool:
        value = (os.getenv("server_doctor_CERTBOT_DRY_RUN") or "0").strip().lower()
        return value in {"1", "true", "yes", "on"}

    def scan(self, nginx_info: NginxInfo | None) -> CertbotModel:
        certbot = CertbotModel()

        certbot.installed = self.ssh.run("which certbot >/dev/null 2>&1 && echo yes || echo no").stdout.strip() == "yes"
        if certbot.installed:
            certbot.service_failed = self.ssh.run("systemctl is-failed certbot.service 2>/dev/null || true").stdout.strip() == "failed"
            certbot.timer_active = self.ssh.run("systemctl is-active certbot.timer 2>/dev/null || true").stdout.strip() == "active"
            certbot.timer_enabled = self.ssh.run("systemctl is-enabled certbot.timer 2>/dev/null || true").stdout.strip() == "enabled"
            certbot.systemctl_status_output = self.ssh.run(
                "systemctl status certbot.service certbot.timer --no-pager -n 80 2>&1 || true",
                timeout=8,
            ).stdout.strip()
            if self._dry_run_enabled():
                certbot.renew_dry_run_output = self.ssh.run(
                    "certbot renew --dry-run 2>&1 || true",
                    timeout=25,
                ).stdout.strip()
            else:
                certbot.renew_dry_run_output = (
                    "skipped (set server_doctor_CERTBOT_DRY_RUN=1 to enable certbot renew --dry-run)"
                )
            certbot.journal_output = self.ssh.run(
                "journalctl -u certbot.service -n 120 --no-pager 2>&1 || true",
                timeout=8,
            ).stdout.strip()
            certbot.unit_cat_output = self.ssh.run(
                "systemctl cat certbot.service certbot.timer 2>&1 || true",
                timeout=8,
            ).stdout.strip()
            certbot.certificates_output = self.ssh.run(
                "certbot certificates 2>&1 || true",
                timeout=8,
            ).stdout.strip()
            certbot.renewal_dir_listing = self.ssh.run(
                "ls -la /etc/letsencrypt/renewal 2>&1 || true",
                timeout=5,
            ).stdout.strip()

        cert_paths = self._extract_letsencrypt_certs(nginx_info)
        certbot.active_cert_paths = cert_paths
        certbot.uses_letsencrypt_certs = bool(cert_paths)
        certbot.https_detected = self._has_https(nginx_info)
        certbot.min_days_to_expiry = self._min_days_to_expiry(cert_paths)
        return certbot

    def _extract_letsencrypt_certs(self, nginx_info: NginxInfo | None) -> list[str]:
        if not nginx_info:
            return []
        seen: set[str] = set()
        paths: list[str] = []
        for server in nginx_info.servers:
            cert_path = (server.ssl_certificate or "").strip()
            if not cert_path:
                continue
            if "/etc/letsencrypt/" not in cert_path:
                continue
            if cert_path in seen:
                continue
            seen.add(cert_path)
            paths.append(cert_path)
        return paths

    def _has_https(self, nginx_info: NginxInfo | None) -> bool:
        if not nginx_info:
            return False
        for server in nginx_info.servers:
            if server.ssl_enabled:
                return True
            for listen in server.listen:
                listen_lower = listen.lower()
                if "443" in listen_lower or "ssl" in listen_lower:
                    return True
        return False

    def _min_days_to_expiry(self, cert_paths: list[str]) -> int | None:
        min_days: int | None = None
        for path in cert_paths:
            res = self.ssh.run(f"openssl x509 -noout -enddate -in {path} 2>/dev/null | cut -d= -f2")
            end_text = res.stdout.strip()
            if not end_text:
                continue
            dt = self._parse_openssl_enddate(end_text)
            if not dt:
                continue
            days = max(0, int((dt - datetime.now(timezone.utc)).total_seconds() // 86400))
            if min_days is None or days < min_days:
                min_days = days
        return min_days

    def _parse_openssl_enddate(self, value: str) -> datetime | None:
        # OpenSSL format typically: "May 10 12:34:56 2026 GMT"
        for fmt in ("%b %d %H:%M:%S %Y %Z", "%b  %d %H:%M:%S %Y %Z"):
            try:
                parsed = datetime.strptime(value, fmt)
                return parsed.replace(tzinfo=timezone.utc)
            except ValueError:
                continue
        return None
