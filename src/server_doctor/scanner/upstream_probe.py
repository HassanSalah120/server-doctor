"""Upstream Probe Scanner - network-aware active probes for backend truth."""

from __future__ import annotations

import os
import re
import shlex
from dataclasses import dataclass

from server_doctor.connector.ssh import SSHConnector
from server_doctor.model.server import NginxInfo, UpstreamProbeResult


@dataclass
class ProbeTarget:
    host: str
    port: int
    likely_ws: bool = False
    ws_paths: list[str] | None = None
    ws_host: str | None = None

    @property
    def key(self) -> str:
        return f"{self.host}:{self.port}"


class UpstreamProbeScanner:
    """Runs layered probes against discovered backend targets."""

    LOCAL_HOSTS = {"127.0.0.1", "localhost", "::1", "[::1]", "0.0.0.0", "::"}

    def __init__(self, ssh: SSHConnector) -> None:
        self.ssh = ssh
        self._ingress_exec_cache: dict[str, bool] = {}

    def scan(self, nginx_info: NginxInfo | None, enabled: bool = True) -> list[UpstreamProbeResult]:
        if not enabled or not nginx_info:
            return []
        ws_enabled = os.getenv("server_doctor_WS_PROBES", "1").strip().lower() not in {"0", "false", "no", "off"}
        targets = self._collect_targets(nginx_info)
        results: list[UpstreamProbeResult] = []
        for target in targets:
            results.append(self._probe_target(nginx_info, target, ws_enabled=ws_enabled))
        return sorted(results, key=lambda r: (r.status != "OPEN", r.target))

    def _collect_targets(self, nginx_info: NginxInfo) -> list[ProbeTarget]:
        targets: dict[str, ProbeTarget] = {}
        upstream_members: dict[str, list[str]] = {}
        for upstream in nginx_info.upstreams:
            upstream_members[upstream.name] = []
            for member in upstream.servers:
                parsed = self._parse_target(member)
                if not parsed:
                    continue
                key = parsed.key
                if key not in targets:
                    parsed.ws_paths = []
                    targets[key] = parsed
                upstream_members[upstream.name].append(key)
        for server in nginx_info.servers:
            for loc in server.locations:
                for raw in (loc.proxy_pass, loc.fastcgi_pass):
                    raw_value = (raw or "").strip()
                    parsed = self._parse_target(raw or "")
                    path = self._normalize_ws_path(loc.path)
                    ws_host = self._pick_ws_host(server.server_names or [])
                    likely_ws = self._location_looks_ws(loc.path)
                    if not parsed:
                        upstream_name = self._extract_upstream_name(raw_value)
                        if not upstream_name:
                            continue
                        for key in upstream_members.get(upstream_name, []):
                            targets[key].likely_ws = targets[key].likely_ws or likely_ws
                            if path:
                                if targets[key].ws_paths is None:
                                    targets[key].ws_paths = []
                                if path not in targets[key].ws_paths:
                                    targets[key].ws_paths.append(path)
                            if not targets[key].ws_host and ws_host:
                                targets[key].ws_host = ws_host
                        continue

                    parsed.likely_ws = parsed.likely_ws or likely_ws
                    key = parsed.key
                    if key in targets:
                        targets[key].likely_ws = targets[key].likely_ws or likely_ws
                        if path:
                            if targets[key].ws_paths is None:
                                targets[key].ws_paths = []
                            if path not in targets[key].ws_paths:
                                targets[key].ws_paths.append(path)
                        if not targets[key].ws_host and ws_host:
                            targets[key].ws_host = ws_host
                    else:
                        parsed.ws_paths = [path] if path else []
                        parsed.ws_host = ws_host
                        targets[key] = parsed
        return list(targets.values())

    def _parse_target(self, raw: str) -> ProbeTarget | None:
        target = raw.strip().rstrip(";")
        if not target:
            return None
        for scheme in ("http://", "https://", "fastcgi://", "grpc://", "grpcs://"):
            if target.startswith(scheme):
                target = target[len(scheme) :]
                break
        if target.startswith("unix:"):
            return None
        if "/" in target:
            target = target.split("/", 1)[0]
        if ":" not in target:
            return None
        host, _, port_s = target.rpartition(":")
        if not host or not port_s.isdigit():
            return None
        return ProbeTarget(host=host, port=int(port_s))

    def _extract_upstream_name(self, target: str) -> str | None:
        cleaned = target.strip().rstrip(";")
        for scheme in ("http://", "https://", "fastcgi://", "grpc://", "grpcs://"):
            if cleaned.startswith(scheme):
                cleaned = cleaned[len(scheme):]
                break
        if "/" in cleaned:
            cleaned = cleaned.split("/", 1)[0]
        if ":" in cleaned or cleaned.startswith("[") or "$" in cleaned:
            return None
        return cleaned if cleaned else None

    def _probe_target(self, nginx_info: NginxInfo, target: ProbeTarget, ws_enabled: bool) -> UpstreamProbeResult:
        scope, runner = self._resolve_probe_scope(nginx_info, target.host)
        # Layer 1: TCP
        tcp_ok, tcp_ms = self._tcp_probe(runner, target.host, target.port)
        # Layer 2: HTTP probe (where meaningful)
        http_code, http_ms = self._http_probe(runner, target.host, target.port)
        # Layer 3: Optional WS handshake
        ws_code = None
        ws_status: str | None = None
        ws_detail: str | None = None
        ws_path: str | None = None
        if ws_enabled and target.likely_ws:
            ws_code, ws_status, ws_detail, ws_path = self._ws_probe(
                runner,
                target.host,
                target.port,
                target.ws_paths or ["/"],
                host_header=target.ws_host or target.host,
            )
            ws_detail = self._refine_ws_detail_from_http_context(
                ws_status=ws_status,
                ws_detail=ws_detail,
                http_code=http_code,
                path=ws_path or ((target.ws_paths or ["/"])[0]),
            )

        reachable = bool(
            tcp_ok
            or (http_code is not None and 100 <= http_code < 500)
            or (ws_code is not None and ws_code in {101, 426})
        )
        status = "OPEN" if reachable else ("UNKNOWN" if scope == "unknown" else "BLOCKED")
        latency = tcp_ms if tcp_ms is not None else http_ms
        detail_parts = [
            f"tcp={'ok' if tcp_ok else 'fail' if tcp_ok is not None else 'n/a'}",
            f"http={http_code if http_code is not None else 'n/a'}",
            f"ws={ws_status if ws_status is not None else (ws_code if ws_code is not None else 'n/a')}",
            f"scope={scope}",
        ]
        return UpstreamProbeResult(
            target=target.key,
            protocol="http" if target.port not in {443, 8443} else "https",
            reachable=reachable,
            latency_ms=latency,
            detail=" ".join(detail_parts),
            scope=scope,
            status=status,
            tcp_ok=tcp_ok,
            http_code=http_code,
            ws_code=ws_code,
            ws_status=ws_status,
            ws_detail=ws_detail,
            ws_path=ws_path,
        )

    def _resolve_probe_scope(self, nginx_info: NginxInfo, host: str):
        is_dns_like = self._is_docker_dns(host)
        if not is_dns_like:
            return "host", self._run_host
        container_id = (nginx_info.container_id or "").strip()
        if not container_id:
            return "unknown", self._run_unknown
        if not self._can_exec_ingress(container_id):
            return "unknown", self._run_unknown
        return "nginx_container", lambda cmd: self._run_container(container_id, cmd)

    def _can_exec_ingress(self, container_id: str) -> bool:
        if container_id in self._ingress_exec_cache:
            return self._ingress_exec_cache[container_id]
        check = self.ssh.run(f"docker exec {container_id} sh -lc 'echo ok' 2>/dev/null", timeout=3)
        ok = check.success and "ok" in (check.stdout or "")
        self._ingress_exec_cache[container_id] = ok
        return ok

    def _tcp_probe(self, runner, host: str, port: int) -> tuple[bool | None, float | None]:
        cmd = (
            f"if command -v nc >/dev/null 2>&1; then "
            f"TIMEFORMAT='%R'; t=$( {{ time nc -z -w 2 {shlex.quote(host)} {port}; }} 2>&1 ); rc=$?; "
            "if [ $rc -eq 0 ]; then echo TCP_OK $t; else echo TCP_FAIL $t; fi; "
            "else echo TCP_NA 0; fi"
        )
        res = runner(cmd)
        out = (res.stdout or "").strip()
        m = re.search(r"^(TCP_OK|TCP_FAIL|TCP_NA)\s+([0-9.]+)$", out)
        if not m:
            return None, None
        tag = m.group(1)
        ms = round(float(m.group(2)) * 1000, 2)
        if tag == "TCP_NA":
            return None, None
        return tag == "TCP_OK", ms

    def _http_probe(self, runner, host: str, port: int) -> tuple[int | None, float | None]:
        scheme = "https" if port in {443, 8443} else "http"
        url = f"{scheme}://{host}:{port}/"
        cmd = (
            "if command -v curl >/dev/null 2>&1; then "
            f"curl -sk -o /dev/null -w '%{{http_code}} %{{time_total}}' --max-time 2 {shlex.quote(url)}; "
            "else echo 000 0.000; fi"
        )
        res = runner(cmd)
        out = (res.stdout or "").strip()
        m = re.search(r"^(\d{3})\s+([0-9.]+)$", out)
        if not m:
            return None, None
        code = int(m.group(1))
        ms = round(float(m.group(2)) * 1000, 2)
        if code == 0 or code == 000:
            return None, None
        return code, ms

    def _ws_probe(
        self,
        runner,
        host: str,
        port: int,
        paths: list[str],
        host_header: str,
    ) -> tuple[int | None, str | None, str | None, str | None]:
        scheme = "https" if port in {443, 8443} else "http"
        probe_paths = [p for p in paths if p and p.startswith("/")] or ["/"]
        fallback: int | None = None
        fallback_status: str | None = None
        fallback_detail: str | None = None
        fallback_path: str | None = None
        for path in probe_paths:
            url = f"{scheme}://{host}:{port}{path}"
            cmd = (
                "if command -v curl >/dev/null 2>&1; then "
                f"out=$(curl -sk -o /dev/null -w '%{{http_code}}' --max-time 2 "
                f"-H 'Connection: Upgrade' -H 'Upgrade: websocket' -H 'Sec-WebSocket-Version: 13' "
                f"-H 'Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==' "
                f"-H 'Host: {host_header}' "
                f"-H 'Origin: {scheme}://{host_header}' "
                f"{shlex.quote(url)}); rc=$?; "
                "if [ $rc -eq 0 ]; then echo $out; "
                "elif [ $rc -eq 28 ]; then echo timeout; "
                "else echo fail; fi; "
                "else echo ''; fi"
            )
            res = runner(cmd)
            out = (res.stdout or "").strip()
            if out.isdigit():
                code = int(out)
                if code == 101:
                    return (101, "101", f"WS handshake succeeded on {path}", path)
                # keep first non-101 code as fallback signal
                if fallback is None:
                    fallback = code
                    fallback_status = str(code)
                    fallback_detail = self._ws_failure_detail(code, path)
                    fallback_path = path
            elif out in {"timeout", "fail"} and fallback_status is None:
                fallback_status = out if out == "timeout" else "handshake_error"
                fallback_detail = (
                    f"timeout after 2s on WS path {path}"
                    if out == "timeout"
                    else f"WS handshake error on {path}"
                )
                fallback_path = path
        if fallback_status is None:
            fallback_status = "handshake_error"
            fallback_detail = "WS handshake error (no response status)"
        return (fallback, fallback_status, fallback_detail, fallback_path)

    @staticmethod
    def _ws_failure_detail(code: int, path: str) -> str:
        if code == 404:
            return (
                f"Upstream returned HTTP 404 on WS path {path} "
                f"(likely wrong WS route/path not registered)."
            )
        if code == 426:
            return (
                f"Upstream returned HTTP 426 on WS path {path} "
                f"(Upgrade required or proxy headers incomplete)."
            )
        if code == 200:
            return (
                f"Upstream returned HTTP 200 on WS path {path} "
                f"(endpoint behaves like HTTP, not WebSocket)."
            )
        if 300 <= code < 400:
            return (
                f"Upstream redirected WS probe with HTTP {code} on {path} "
                f"(redirects can break handshake)."
            )
        if code >= 500:
            return f"Upstream returned HTTP {code} on WS path {path} (backend/server error)."
        return f"Upstream returned HTTP {code} on WS path {path}."

    @staticmethod
    def _refine_ws_detail_from_http_context(
        ws_status: str | None,
        ws_detail: str | None,
        http_code: int | None,
        path: str,
    ) -> str | None:
        if ws_status != "handshake_error":
            return ws_detail
        # Use layered probe context to turn generic handshake_error into actionable reason.
        if http_code == 404:
            return (
                f"404 at upstream for {path} -> likely wrong WS path "
                f"(try trailing slash variant or /socket.io/ if applicable)."
            )
        if http_code == 426:
            return (
                f"426 at upstream for {path} -> likely missing/incorrect Upgrade or Connection headers."
            )
        if http_code == 200:
            return f"200 at upstream for {path} -> endpoint appears HTTP-only, not WebSocket."
        if ws_detail:
            return ws_detail
        return "WS handshake error (reason unknown from probe context)."

    def _run_host(self, cmd: str):
        return self.ssh.run(f"sh -lc \"{cmd}\"", timeout=5)

    def _run_container(self, container_id: str, cmd: str):
        safe = cmd.replace('"', '\\"')
        return self.ssh.run(f"docker exec {container_id} sh -lc \"{safe}\"", timeout=6)

    def _run_unknown(self, cmd: str):
        # unable to run probe in required scope
        class _R:
            success = False
            stdout = ""
        return _R()

    @staticmethod
    def _is_docker_dns(host: str) -> bool:
        h = host.strip().lower()
        if not h or h in UpstreamProbeScanner.LOCAL_HOSTS:
            return False
        # IPs or bracketed IPv6 are not Docker DNS service names.
        if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", h):
            return False
        if h.startswith("[") and h.endswith("]"):
            return False
        # Plain hostname-ish target treated as docker/internal DNS candidate.
        return bool(re.match(r"^[a-z0-9][a-z0-9_.-]*$", h))

    @staticmethod
    def _location_looks_ws(path: str) -> bool:
        p = (path or "").lower()
        return "/ws" in p or "socket.io" in p or "websocket" in p

    @staticmethod
    def _normalize_ws_path(path: str) -> str | None:
        p = (path or "").strip()
        if not p:
            return None
        if p.startswith("="):
            p = p[1:].strip()
        elif p.startswith("^~"):
            p = p[2:].strip()
        if p.startswith("~"):
            return None
        if not p.startswith("/"):
            return None
        return p

    @staticmethod
    def _pick_ws_host(server_names: list[str]) -> str | None:
        for name in server_names:
            n = (name or "").strip()
            if not n or n in {"_", "default"} or n.startswith("*"):
                continue
            return n
        return None
