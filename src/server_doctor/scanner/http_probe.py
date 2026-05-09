"""Read-only HTTP/HTTPS endpoint probing."""

from __future__ import annotations

import base64
import secrets
import ssl
import time

import requests

from server_doctor.model.server import (
    HttpProbeModel,
    HttpProbeResult,
    NginxInfo,
    ServerBlock,
)

SENSITIVE_PATHS = [
    "/.env",
    "/.git/config",
    "/composer.json",
    "/package.json",
    "/vendor/",
    "/storage/logs/",
]


def probe_url(
    url: str,
    *,
    method: str = "GET",
    timeout: float = 5.0,
    max_redirects: int = 5,
) -> HttpProbeResult:
    """Probe one URL with bounded redirects and a 4 KiB body sample."""
    started = time.monotonic()
    session = requests.Session()
    session.max_redirects = max_redirects
    try:
        response = session.request(
            method,
            url,
            allow_redirects=True,
            timeout=timeout,
            stream=True,
            headers={"User-Agent": "ServerDoctor/diagnostic-probe"},
        )
        sample = ""
        if method.upper() != "HEAD":
            sample = response.raw.read(4096, decode_content=True).decode(
                response.encoding or "utf-8",
                errors="replace",
            )
        tls_subject = None
        tls_issuer = None
        tls_not_after = None
        cert = _extract_peer_cert(response)
        if cert:
            tls_subject = _format_cert_name(cert.get("subject"))
            tls_issuer = _format_cert_name(cert.get("issuer"))
            tls_not_after = cert.get("notAfter")
        return HttpProbeResult(
            url=url,
            method=method.upper(),
            status_code=response.status_code,
            final_url=response.url,
            redirect_chain=[item.url for item in response.history],
            headers={str(k).lower(): str(v) for k, v in response.headers.items()},
            body_sample=sample,
            error=None,
            elapsed_ms=int((time.monotonic() - started) * 1000),
            tls_subject=tls_subject,
            tls_issuer=tls_issuer,
            tls_not_after=tls_not_after,
        )
    except requests.TooManyRedirects as exc:
        return _error_result(url, method, started, "redirect_loop", exc.response)
    except requests.RequestException as exc:
        return _error_result(url, method, started, str(exc), None)


def probe_websocket(
    url: str,
    *,
    timeout: float = 5.0,
) -> HttpProbeResult:
    """Send a proper RFC 6455 WebSocket upgrade request."""
    started = time.monotonic()
    key = base64.b64encode(secrets.token_bytes(16)).decode()
    headers = {
        "Connection": "Upgrade",
        "Upgrade": "websocket",
        "Sec-WebSocket-Key": key,
        "Sec-WebSocket-Version": "13",
        "User-Agent": "ServerDoctor/diagnostic-probe",
    }
    session = requests.Session()
    try:
        response = session.request(
            "GET",
            url,
            allow_redirects=False,
            timeout=timeout,
            headers=headers,
            stream=True,
        )
        return HttpProbeResult(
            url=url,
            method="GET",
            status_code=response.status_code,
            final_url=response.url,
            redirect_chain=[item.url for item in response.history],
            headers={str(k).lower(): str(v) for k, v in response.headers.items()},
            body_sample=None,
            error=None,
            elapsed_ms=int((time.monotonic() - started) * 1000),
        )
    except requests.Timeout:
        return _error_result(url, "GET", started, "timeout", None)
    except requests.exceptions.SSLError:
        return _error_result(url, "GET", started, "tls_error", None)
    except requests.ConnectionError:
        return _error_result(url, "GET", started, "connection_refused", None)
    except requests.RequestException as exc:
        return _error_result(url, "GET", started, str(exc), None)


class HttpProbeScanner:
    """Build probe targets from Nginx server names and observed locations."""

    def __init__(self, ssh=None) -> None:
        self.ssh = ssh

    def scan(self, nginx: NginxInfo | None = None) -> HttpProbeModel:
        if nginx is None:
            return HttpProbeModel(enabled=False, notes=["No Nginx model available"])
        results: list[HttpProbeResult] = []
        for server in nginx.servers:
            for base_url in _server_base_urls(server):
                results.append(probe_url(base_url, method="GET"))
                for path in SENSITIVE_PATHS:
                    results.append(probe_url(base_url.rstrip("/") + path, method="GET"))
                if _has_websocket_location(server):
                    ws_paths = _websocket_location_paths(server)
                    if ws_paths:
                        for ws_path in ws_paths:
                            results.append(
                                probe_websocket(base_url.rstrip("/") + ws_path)
                            )
                    else:
                        results.append(
                            probe_websocket(base_url.rstrip("/") + "/__serverdoctor_ws_probe__")
                        )
        return HttpProbeModel(enabled=True, results=results)


def _server_base_urls(server: ServerBlock) -> list[str]:
    names = [name for name in server.server_names if name and name != "_"]
    if not names:
        return []
    listen_text = " ".join(server.listen).lower()
    schemes = ["https"] if server.ssl_enabled or "443" in listen_text else ["http"]
    if "80" in listen_text and "https" not in schemes:
        schemes.append("http")
    return [f"{scheme}://{names[0]}" for scheme in schemes]


def _has_websocket_location(server: ServerBlock) -> bool:
    for location in server.locations:
        headers = {k.lower(): v.lower() for k, v in location.proxy_set_headers.items()}
        if "upgrade" in headers or "upgrade" in (location.proxy_http_version or "").lower():
            return True
        if "ws" in location.path.lower() or "websocket" in location.path.lower():
            return True
    return False


def _websocket_location_paths(server: ServerBlock) -> list[str]:
    """Return location paths that appear to be WebSocket endpoints."""
    paths = []
    for location in server.locations:
        headers = {k.lower(): v.lower() for k, v in location.proxy_set_headers.items()}
        path = location.path.lower()
        if "upgrade" in headers or "ws" in path or "websocket" in path:
            paths.append(location.path)
    return paths


def _error_result(
    url: str,
    method: str,
    started: float,
    error: str,
    response: requests.Response | None,
) -> HttpProbeResult:
    return HttpProbeResult(
        url=url,
        method=method.upper(),
        status_code=getattr(response, "status_code", None),
        final_url=getattr(response, "url", None),
        redirect_chain=[],
        headers={},
        body_sample=None,
        error=error,
        elapsed_ms=int((time.monotonic() - started) * 1000),
    )


def _extract_peer_cert(response: requests.Response) -> dict | None:
    try:
        sock = response.raw.connection.sock
        if isinstance(sock, ssl.SSLSocket):
            return sock.getpeercert()
    except Exception:
        return None
    return None


def _format_cert_name(value: object) -> str | None:
    if not value:
        return None
    try:
        return ", ".join("=".join(item) for group in value for item in group)
    except Exception:
        return str(value)


def is_exposed_sensitive_path(result: HttpProbeResult) -> bool:
    """Return True when a sensitive path exposes content-specific sensitive data."""
    if result.status_code not in {200, 206}:
        return False
    return _sensitive_content_kind(result) is not None


def is_sensitive_path_soft_404(result: HttpProbeResult) -> bool:
    """Return True when a sensitive path is answered by an HTML/SPA fallback."""
    if result.status_code != 200:
        return False
    if _sensitive_content_kind(result) is not None:
        return False
    sample = (result.body_sample or "").lower()
    content_type = result.headers.get("content-type", "").lower()
    return _looks_like_html_fallback(sample, content_type)


def _sensitive_content_kind(result: HttpProbeResult) -> str | None:
    sample = (result.body_sample or "").lower()
    path = result.url.split("?", 1)[0].rstrip("/").lower()
    if path.endswith("/.env"):
        markers = ("app_key", "db_password", "db_host", "secret", "token")
        return ".env" if any(marker in sample for marker in markers) else None
    if path.endswith("/.git/config"):
        if "[core]" in sample and "repositoryformatversion" in sample:
            return "git-config"
        return None
    if path.endswith("/composer.json"):
        markers = ('"require"', '"autoload"', '"scripts"', '"config"')
        return "composer-json" if any(marker in sample for marker in markers) else None
    if path.endswith("/package.json"):
        markers = ('"dependencies"', '"devdependencies"', '"scripts"', '"name"')
        return "package-json" if any(marker in sample for marker in markers) else None
    if path.endswith("/vendor"):
        markers = ("index of /vendor", "autoload.php", "composer")
        return "vendor-listing" if any(marker in sample for marker in markers) else None
    if path.endswith("/storage/logs"):
        markers = ("index of /storage/logs", "laravel.log", "production.error")
        return "log-listing" if any(marker in sample for marker in markers) else None
    return None


def _looks_like_html_fallback(sample: str, content_type: str) -> bool:
    if "text/html" in content_type:
        return True
    html_markers = (
        "<!doctype html",
        "<html",
        "<div id=\"root\"",
        "<div id='root'",
        "type=\"module\"",
        "type='module'",
        "/assets/",
    )
    return any(marker in sample for marker in html_markers)
