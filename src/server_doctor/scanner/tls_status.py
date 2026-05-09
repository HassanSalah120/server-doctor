"""TLS Status Scanner - live TLS inspection using openssl s_client + SNI."""

from __future__ import annotations

import datetime
import ipaddress
import os

from server_doctor.connector.ssh import SSHConnector
from server_doctor.model.server import NginxInfo, TLSCertificateStatus, TLSStatusModel


class TLSStatusScanner:
    """Collect TLS metadata from live handshake rather than file parsing."""

    def __init__(self, ssh: SSHConnector) -> None:
        self.ssh = ssh

    @staticmethod
    def _max_targets() -> int:
        try:
            return max(1, int(os.getenv("server_doctor_TLS_MAX_TARGETS", "12")))
        except ValueError:
            return 12

    @staticmethod
    def _probe_timeout() -> float:
        try:
            return max(2.0, float(os.getenv("server_doctor_TLS_PROBE_TIMEOUT", "4")))
        except ValueError:
            return 4.0

    @staticmethod
    def _shell_quote(value: str) -> str:
        return "'" + value.replace("'", "'\"'\"'") + "'"

    @staticmethod
    def _is_ip(value: str) -> bool:
        try:
            ipaddress.ip_address(value)
            return True
        except ValueError:
            return False

    def _is_valid_sni(self, value: str) -> bool:
        sni = (value or "").strip().lower()
        if not sni or sni in {"_", "default"} or sni.startswith("*"):
            return False
        if self._is_ip(sni):
            return False
        allowed = set("abcdefghijklmnopqrstuvwxyz0123456789.-")
        return all(ch in allowed for ch in sni)

    @staticmethod
    def _target_priority(item: tuple[str, int]) -> tuple[int, str, int]:
        sni, port = item
        local_penalty = 1 if sni in {"localhost", "localhost.localdomain"} else 0
        return (local_penalty, sni, port)

    def scan(self, nginx_info: NginxInfo | None) -> TLSStatusModel:
        if not nginx_info:
            return TLSStatusModel()
        sni_targets = self._collect_sni_targets(nginx_info)
        certs: list[TLSCertificateStatus] = []
        for sni, connect_port in sni_targets:
            certs.append(self._inspect_live_cert(sni, connect_port, nginx_info))
        return TLSStatusModel(certificates=certs)

    def _collect_sni_targets(self, nginx_info: NginxInfo) -> list[tuple[str, int]]:
        targets: set[tuple[str, int]] = set()
        for server in nginx_info.servers:
            listens = [self._extract_listen_port(v) for v in (server.listen or [])]
            ssl_like = server.ssl_enabled or any("ssl" in (l or "").lower() for l in (server.listen or []))
            if not ssl_like and not any(p == 443 for p in listens if p is not None):
                continue
            port = next((p for p in listens if p), 443) or 443
            for name in (server.server_names or []):
                sni = (name or "").strip()
                if not self._is_valid_sni(sni):
                    continue
                targets.add((sni, port))
        ordered = sorted(targets, key=self._target_priority)
        return ordered[: self._max_targets()]

    def _inspect_live_cert(
        self,
        sni: str,
        port: int,
        nginx_info: NginxInfo,
    ) -> TLSCertificateStatus:
        connect = f"127.0.0.1:{port}"
        path = f"live://{sni}@{connect}"
        status = TLSCertificateStatus(path=path)
        sni_q = self._shell_quote(sni)
        connect_q = self._shell_quote(connect)
        cmd = (
            "sh -lc \""
            f"echo | openssl s_client -servername {sni_q} -connect {connect_q} 2>/dev/null "
            "| openssl x509 -noout -issuer -subject -enddate -ext subjectAltName 2>/dev/null\""
        )
        probe_timeout = self._probe_timeout()
        res = self._run_probe(cmd, timeout=probe_timeout)
        if not res.success or not (res.stdout or "").strip():
            # Retry once with a longer timeout to reduce transient handshake misses.
            res = self._run_probe(cmd, timeout=max(6.0, probe_timeout * 2))

        if res.success and (res.stdout or "").strip():
            self._parse_cert_output(status, res.stdout or "")
            return status

        # Fallback: parse certificate directly from nginx ssl_certificate file.
        cert_path = self._find_cert_path(nginx_info, sni, port)
        if cert_path:
            cert_q = self._shell_quote(cert_path)
            file_cmd = (
                "sh -lc \""
                f"openssl x509 -in {cert_q} -noout -issuer -subject -enddate -ext subjectAltName 2>/dev/null\""
            )
            file_res = self.ssh.run(file_cmd, timeout=max(6.0, probe_timeout * 2))
            if file_res.success and (file_res.stdout or "").strip():
                self._parse_cert_output(status, file_res.stdout or "")
                return status

        status.parse_ok = False
        return status

    def _run_probe(self, command: str, *, timeout: float):
        """Run a probe without sudo when supported by the SSH backend."""
        try:
            return self.ssh.run(command, timeout=timeout, use_sudo=False)
        except TypeError:
            # Some lightweight test doubles or alternate backends do not accept
            # the ``use_sudo`` keyword. Fall back to the older call shape.
            return self.ssh.run(command, timeout=timeout)

    def _parse_cert_output(self, status: TLSCertificateStatus, output: str) -> None:
        lines = [line.strip() for line in output.splitlines() if line.strip()]
        for line in lines:
            if line.startswith("issuer="):
                status.issuer = line[len("issuer=") :].strip()
            elif line.startswith("subject="):
                status.subject = line[len("subject=") :].strip()
            elif line.startswith("notAfter="):
                status.expires_at = line[len("notAfter=") :].strip()
            elif "DNS:" in line:
                sans = [s.strip().replace("DNS:", "") for s in line.split(",") if "DNS:" in s]
                status.sans.extend([s for s in sans if s and s not in status.sans])
        status.days_remaining = self._days_until_expiry(status.expires_at)
        status.parse_ok = True

    def _find_cert_path(self, nginx_info: NginxInfo, sni: str, port: int) -> str | None:
        for server in nginx_info.servers:
            names = {(name or "").strip().lower() for name in (server.server_names or [])}
            if sni.lower() not in names:
                continue
            listens = [self._extract_listen_port(v) for v in (server.listen or [])]
            listen_port = next((p for p in listens if p), 443) or 443
            if listen_port != port:
                continue
            cert_path = (server.ssl_certificate or "").strip()
            if cert_path:
                return cert_path
        return None

    def _days_until_expiry(self, expires: str | None) -> int | None:
        if not expires:
            return None
        for fmt in ("%b %d %H:%M:%S %Y %Z", "%b  %d %H:%M:%S %Y %Z"):
            try:
                dt = datetime.datetime.strptime(expires, fmt).replace(tzinfo=datetime.timezone.utc)
                now = datetime.datetime.now(datetime.timezone.utc)
                return max(0, int((dt - now).total_seconds() // 86400))
            except ValueError:
                continue
        return None

    @staticmethod
    def _extract_listen_port(listen: str) -> int | None:
        value = (listen or "").split()[0]
        if "]:" in value:
            value = value.rsplit("]:", 1)[1]
        elif ":" in value and not value.startswith("["):
            value = value.rsplit(":", 1)[1]
        return int(value) if value.isdigit() else None
