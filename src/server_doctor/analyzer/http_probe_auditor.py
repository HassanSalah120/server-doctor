"""Audit live HTTP probe results."""

from __future__ import annotations

import re
import shlex
from urllib.parse import urlparse

from server_doctor.model.evidence import Evidence, Severity
from server_doctor.model.finding import Finding
from server_doctor.model.server import HttpProbeResult, LocationBlock, ServerBlock, ServerModel
from server_doctor.scanner.http_probe import (
    is_exposed_sensitive_path,
    is_sensitive_path_soft_404,
)


class HttpProbeAuditor:
    def __init__(self, model: ServerModel) -> None:
        self.model = model

    def _find_location_for_path(self, path: str) -> tuple[ServerBlock | None, LocationBlock | None]:
        """Find the Nginx location block matching a given URL path."""
        path = path.rstrip("/") or "/"
        best: LocationBlock | None = None
        best_server: ServerBlock | None = None
        for server in (self.model.nginx.servers or []) if self.model.nginx else []:
            for loc in server.locations:
                loc_path = loc.path.rstrip("/") or "/"
                if loc_path == path:
                    return server, loc
                if path.startswith(loc_path) and (
                    best is None or len(loc_path) > len(best.path.rstrip("/") or "/")
                ):
                    best = loc
                    best_server = server
        return best_server, best

    def _resolve_upstream_targets(self, proxy_pass: str) -> list[str]:
        """Resolve proxy_pass target to backend addresses via upstreams if available."""
        # Extract upstream name from proxy_pass like http://backend_ws or http://backend_ws/
        m = re.match(r"https?://([^/]+)", proxy_pass)
        if not m:
            return [proxy_pass]
        target = m.group(1)
        # Check if it matches an upstream block
        for up in (self.model.nginx.upstreams or []) if self.model.nginx else []:
            if up.name == target:
                return up.servers[:]
        return [target]

    def _check_docker_port(self, host: str, port: int) -> str | None:
        """Check if a host:port maps to a Docker container. Returns container name or None."""
        for c in (self.model.services.docker_containers or []):
            for p in c.ports:
                if p.host_port == port:
                    return f"docker:{c.name}"
                if p.container_port == port:
                    return f"docker:{c.name}"
        return None

    def _classify_ws_cause(
        self,
        path: str,
        error_reason: str,
        status_code: int | None,
    ) -> dict[str, str]:
        """Classify WebSocket failure cause by correlating with topology."""
        result: dict[str, str] = {
            "cause_class": "unknown",
            "upstream": "",
            "backend": "",
            "container": "",
            "detail": "",
        }
        server, loc = self._find_location_for_path(path)
        if not loc:
            return result

        result["detail"] = f"nginx location: {loc.path} (source: {loc.source_file})"

        if loc.proxy_http_version != "1.1":
            result["cause_class"] = "nginx_missing_upgrade_headers"
            result["detail"] += "; proxy_http_version is not 1.1 (required for WebSocket)"
            return result

        proxy = loc.proxy_pass
        if not proxy and loc.fastcgi_pass:
            result["cause_class"] = "nginx_fastcgi_not_ws_compatible"
            result["detail"] += "; location uses fastcgi_pass, not proxy_pass"
            return result
        if not proxy:
            result["cause_class"] = "nginx_no_proxy_pass"
            result["detail"] += "; location has no proxy_pass"
            return result

        result["upstream"] = proxy
        targets = self._resolve_upstream_targets(proxy)
        result["backend"] = ", ".join(targets) if targets else proxy

        if targets:
            for t in targets:
                # Parse host:port from target
                port_match = re.search(r":(\d+)$", t)
                host_part = t.split(":")[0] if ":" in t else t
                port = int(port_match.group(1)) if port_match else None
                if port:
                    container = self._check_docker_port(host_part, port)
                    if container:
                        result["container"] = container
                        result["detail"] += f"; mapped to {container} on {t}"

        if status_code is None:
            if "refused" in error_reason.lower():
                if result["container"]:
                    result["cause_class"] = "upstream_port_not_listening"
                else:
                    result["cause_class"] = "probe_connection_refused"
            elif "timeout" in error_reason.lower():
                result["cause_class"] = "upstream_timeout"
            else:
                result["cause_class"] = "probe_connection_refused"
        elif status_code == 200:
            result["cause_class"] = "backend_rejected_handshake"
            result["detail"] += "; backend returned 200 instead of 101 Switching Protocols"

        return result

    def audit(self) -> list[Finding]:
        findings: list[Finding] = []
        for result in self.model.http_probes.results:
            if result.error == "redirect_loop":
                findings.append(_finding(
                    "HTTP-PROBE-002",
                    Severity.CRITICAL,
                    "HTTP/HTTPS redirect loop detected",
                    f"Probe for {result.url} exceeded the redirect limit.",
                    result,
                    "Fix the redirect rules so the request reaches a final URL.",
                    ["Users may be unable to load the site."],
                ))
                continue
            if result.final_url and _downgrades_to_http(result):
                findings.append(_finding(
                    "HTTP-PROBE-003",
                    Severity.CRITICAL,
                    "HTTPS redirects to HTTP",
                    f"{result.url} ended at insecure URL {result.final_url}.",
                    result,
                    "Remove HTTPS-to-HTTP redirects and make HTTPS the final scheme.",
                    ["Session cookies and credentials may be exposed in transit."],
                ))
            if _missing_https_redirect(result):
                findings.append(_finding(
                    "HTTP-PROBE-004",
                    Severity.WARNING,
                    "HTTP does not redirect to HTTPS",
                    f"{result.url} returned HTTP {result.status_code} without HTTPS redirect.",
                    result,
                    "Add a port 80 redirect to the canonical HTTPS URL.",
                    ["Users may remain on plaintext HTTP."],
                ))
            if result.status_code in {502, 503, 504}:
                findings.append(_finding(
                    "HTTP-PROBE-007",
                    Severity.CRITICAL,
                    f"Upstream failure at {result.url}",
                    f"Live probe returned HTTP {result.status_code}.",
                    result,
                    "Check proxy_pass/fastcgi_pass target, service status, and ports.",
                    ["Users may see gateway errors or application downtime."],
                ))
            elif result.status_code and result.status_code >= 500:
                findings.append(_finding(
                    "HTTP-PROBE-001",
                    Severity.CRITICAL,
                    f"HTTPS returns HTTP {result.status_code}",
                    f"Live probe returned server error HTTP {result.status_code}.",
                    result,
                    "Inspect application and web server logs for the failing endpoint.",
                    ["Users may see server errors."],
                ))
            if _is_sensitive_url(result.url) and is_exposed_sensitive_path(result):
                findings.append(_finding(
                    "HTTP-PROBE-005",
                    Severity.CRITICAL,
                    "Sensitive path is publicly exposed",
                    f"{result.url} returned HTTP {result.status_code}.",
                    result,
                    "Block dotfiles, dependency manifests, logs, and private app paths.",
                    ["Secrets or source metadata may be exposed publicly."],
                ))
            elif _is_sensitive_url(result.url) and is_sensitive_path_soft_404(result):
                findings.append(_finding(
                    "HTTP-PROBE-SOFT404",
                    Severity.WARNING,
                    "Sensitive path returns SPA fallback with HTTP 200",
                    (
                        f"{result.url} returned HTTP 200, but the sampled body does not "
                        "match sensitive file markers."
                    ),
                    result,
                    (
                        "Return 403 or 404 for sensitive paths before the SPA fallback "
                        "location."
                    ),
                    [
                        "This is not confirmed secret exposure, but it is a soft-404 "
                        "routing issue."
                    ],
                ))
            if result.status_code is not None and _is_generic_sensitive_path(result.url):
                if result.status_code in {401, 403}:
                    pass
                elif _is_route_protected(result):
                    findings.append(_finding(
                        "HTTP-PROBE-008",
                        Severity.INFO,
                        f"Sensitive route '{urlparse(result.url).path}' requires authentication",
                        (
                            f"{result.url} returns login/authentication page. "
                            "Route is likely protected."
                        ),
                        result,
                        "No action needed if authentication covers all sensitive functionality.",
                        ["Route appears to require authentication"],
                    ))
                elif result.status_code == 200:
                    sample = (result.body_sample or "").lower()
                    admin_markers = {
                        "admin dashboard",
                        "admin panel",
                        "user management",
                        "configuration",
                    }
                    if any(marker in sample for marker in admin_markers):
                        severity = Severity.WARNING
                        conf = 0.8
                        extra = "probe-confirmed: 200 with admin markers"
                        condition = (
                            f"Probe confirms route '{urlparse(result.url).path}' "
                            "is publicly accessible"
                        )
                    else:
                        severity = Severity.INFO
                        conf = 0.4
                        extra = "route-name-only: 200 generic response, no admin markers"
                        condition = (
                            f"Route name '{urlparse(result.url).path}' matches "
                            "sensitive pattern (unconfirmed)"
                        )
                    findings.append(
                        Finding(
                            id="HTTP-PROBE-008",
                            severity=severity,
                            confidence=conf,
                            condition=condition,
                            cause=(
                                f"{result.url} returned HTTP 200 with no "
                                "authentication indicators."
                            ),
                            evidence=[
                                Evidence(
                                    source_file="http probe",
                                    line_number=0,
                                    excerpt=f"{result.url} => HTTP {result.status_code}; {extra}",
                                    command=f"curl -I -L --max-redirs 5 {shlex.quote(result.url)}",
                                )
                            ],
                            treatment=(
                                "Restrict access with authentication (auth_basic, OAuth) "
                                "or IP allowlist."
                            ),
                            impact=["Admin/dashboard interface reachable without authentication"],
                        )
                    )
            if _looks_like_websocket_probe(result):
                # Socket.io responds with 200 to raw WS upgrade (uses Engine.IO HTTP transport).
                # This is not a WebSocket failure — Socket.io is working correctly.
                if _is_socketio_path(result.url) and result.status_code == 200:
                    continue
                # Correlate with topology for cause classification
                ws_cause = self._classify_ws_cause(
                    urlparse(result.url).path,
                    result.error or "",
                    result.status_code,
                )
                cause_detail = ws_cause.get("detail", "")
                cause_class = ws_cause.get("cause_class", "unknown")
                backend = ws_cause.get("backend", "")
                container = ws_cause.get("container", "")

                evidence_lines = [
                    f"{result.url} => HTTP {result.status_code}; error={result.error}",
                ]
                evidence_lines.append(f"cause_class={cause_class}")
                if backend:
                    evidence_lines.append(f"upstream_target={backend}")
                if container:
                    evidence_lines.append(f"container={container}")
                if cause_detail:
                    evidence_lines.append(f"detail={cause_detail[:200]}")

                if result.status_code is None:
                    error_reason = result.error or "connection failed"
                    if "timeout" in error_reason.lower():
                        display = "WebSocket probe timed out"
                    elif "refused" in error_reason.lower():
                        display = "WebSocket connection refused"
                    elif "ssl" in error_reason.lower() or "tls" in error_reason.lower():
                        display = "WebSocket TLS connection failed"
                    elif "dns" in error_reason.lower():
                        display = "WebSocket DNS resolution failed"
                    else:
                        display = f"WebSocket connection failed: {error_reason}"
                    findings.append(_ws_finding(
                        "HTTP-PROBE-006",
                        Severity.WARNING,
                        display,
                        f"WebSocket probe could not complete: {error_reason}.",
                        result,
                        "Verify Upgrade and Connection headers and upstream WebSocket service.",
                        ["Realtime features may fail for clients."],
                        evidence_lines,
                    ))
                elif result.status_code not in {101, 400, 426}:
                    findings.append(_ws_finding(
                        "HTTP-PROBE-006",
                        Severity.WARNING,
                        f"WebSocket upgrade returned HTTP {result.status_code}, expected 101",
                        (
                            f"WebSocket probe returned HTTP {result.status_code} "
                            "instead of 101 Switching Protocols."
                        ),
                        result,
                        "Verify Upgrade and Connection headers and upstream WebSocket service.",
                        ["Realtime features may fail for clients."],
                        evidence_lines,
                    ))
        return findings


def _finding(
    rule_id: str,
    severity: Severity,
    condition: str,
    cause: str,
    result: HttpProbeResult,
    treatment: str,
    impact: list[str],
) -> Finding:
    return Finding(
        id=rule_id,
        severity=severity,
        confidence=0.95,
        condition=condition,
        cause=cause,
        evidence=[
            Evidence(
                source_file="http probe",
                line_number=0,
                excerpt=(
                    f"{result.url} => HTTP {result.status_code}; "
                    f"final_url={result.final_url}; error={result.error}"
                ),
                command=f"curl -I -L --max-redirs 5 {shlex.quote(result.url)}",
            )
        ],
        treatment=treatment,
        impact=impact,
    )


def _ws_finding(
    rule_id: str,
    severity: Severity,
    condition: str,
    cause: str,
    result: HttpProbeResult,
    treatment: str,
    impact: list[str],
    evidence_lines: list[str],
) -> Finding:
    return Finding(
        id=rule_id,
        severity=severity,
        confidence=0.95,
        condition=condition,
        cause=cause,
        evidence=[
            Evidence(
                source_file="http probe",
                line_number=0,
                excerpt=" | ".join(evidence_lines),
                command=f"curl -I -L --max-redirs 5 {shlex.quote(result.url)}",
            )
        ],
        treatment=treatment,
        impact=impact,
    )


def _downgrades_to_http(result: HttpProbeResult) -> bool:
    return result.url.startswith("https://") and result.final_url.startswith("http://")


def _missing_https_redirect(result: HttpProbeResult) -> bool:
    if not result.url.startswith("http://") or result.status_code in {301, 302, 307, 308}:
        return False
    return result.status_code is not None and result.status_code < 500


def _is_route_protected(result: HttpProbeResult) -> bool:
    """Return True when the probe response suggests authentication is required."""
    if result.status_code in {401, 403}:
        return True
    sample = (result.body_sample or "").lower()
    login_markers = ("login", "sign in", "password")
    return any(marker in sample for marker in login_markers)


def _is_generic_sensitive_path(url: str) -> bool:
    """Return True for admin/API/auth dashboard-like URL paths."""
    path = urlparse(url).path.lower()
    tokens = ("/admin", "/api", "/auth", "/dashboard", "/wp-admin", "/wp-login")
    return any(token in path for token in tokens)


def _is_sensitive_url(url: str) -> bool:
    path = urlparse(url).path.rstrip("/") or "/"
    return path in {
        "/.env",
        "/.git/config",
        "/composer.json",
        "/package.json",
        "/vendor",
        "/storage/logs",
    }


_WS_PATH_MARKERS = {"/ws", "/wss", "/socket.io", "/cable", "/sockjs"}


def _is_socketio_path(url: str) -> bool:
    return "/socket.io" in urlparse(url).path.lower()


def _looks_like_websocket_probe(result: HttpProbeResult) -> bool:
    if "__serverdoctor_ws_probe__" in result.url:
        return True
    path = urlparse(result.url).path.rstrip("/") or "/"
    if path in _WS_PATH_MARKERS:
        return True
    return "/ws" in path
