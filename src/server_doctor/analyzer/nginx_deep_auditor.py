"""Deeper Nginx configuration diagnosis."""

from __future__ import annotations

from collections import defaultdict

from server_doctor.model.evidence import Evidence, Severity
from server_doctor.model.finding import Finding
from server_doctor.model.server import LocationBlock, ServerBlock, ServerModel


class NginxDeepAuditor:
    def __init__(self, model: ServerModel) -> None:
        self.model = model

    def audit(self) -> list[Finding]:
        nginx = self.model.nginx
        if not nginx:
            return []
        findings: list[Finding] = []
        findings.extend(find_duplicate_server_names(nginx.servers))
        for server in nginx.servers:
            findings.extend(_audit_server(server, self.model))
        return findings


def find_duplicate_server_names(servers: list[ServerBlock]) -> list[Finding]:
    seen: dict[tuple[str, str], ServerBlock] = {}
    findings: list[Finding] = []
    for server in servers:
        listen_key = ",".join(sorted(server.listen or []))
        for name in server.server_names or []:
            key = (listen_key, name)
            previous = seen.get(key)
            if previous:
                findings.append(Finding(
                    id="NGX-DEEP-001",
                    severity=Severity.WARNING,
                    confidence=0.9,
                    condition=f"Duplicate server_name {name}",
                    cause=(
                        "Two Nginx server blocks use the same server_name on "
                        "the same listen address."
                    ),
                    evidence=[
                        Evidence(
                            previous.source_file,
                            previous.line_number,
                            f"server_name {name}",
                            "nginx -T",
                        ),
                        Evidence(
                            server.source_file,
                            server.line_number,
                            f"server_name {name}",
                            "nginx -T",
                        ),
                    ],
                    treatment=(
                        "Merge the duplicate server blocks or make "
                        "server_name/listen values unique."
                    ),
                    impact=["Nginx may route traffic to an unexpected server block."],
                ))
            else:
                seen[key] = server
    return findings


def has_proxy_slash_mismatch(location: LocationBlock) -> bool:
    if not location.proxy_pass:
        return False
    return location.path.endswith("/") != location.proxy_pass.endswith("/")


def _audit_server(server: ServerBlock, model: ServerModel) -> list[Finding]:
    findings: list[Finding] = []
    is_reverse_proxy = not server.root and any(loc.proxy_pass for loc in server.locations)
    project = _project_for_root(model, server.root)
    if project and str(project.type.value).lower() == "laravel":
        if server.root and not server.root.rstrip("/").endswith("/public"):
            findings.append(_server_finding(
                "NGX-DEEP-005",
                Severity.CRITICAL,
                "Laravel Nginx root does not point to /public",
                f"Nginx root is {server.root}, but Laravel should serve public/.",
                server,
                f"root {server.root}",
            ))
        if not _has_try_files(server, "index.php"):
            findings.append(_server_finding(
                "NGX-DEEP-006",
                Severity.WARNING,
                "Laravel try_files fallback is missing",
                "No location contains a Laravel-style try_files fallback.",
                server,
                "try_files ... /index.php",
            ))
    if _looks_like_spa(project) and not _has_try_files(server, "index.html"):
        findings.append(_server_finding(
            "NGX-DEEP-007",
            Severity.WARNING,
            "SPA fallback is missing",
            "React/Vue SPA routes may 404 without try_files fallback to index.html.",
            server,
            "try_files ... /index.html",
        ))
    if not is_reverse_proxy and server.autoindex:
        findings.append(_server_finding(
            "NGX-DEEP-015",
            Severity.CRITICAL,
            "Nginx autoindex is enabled",
            "Directory listings are enabled for a public server block.",
            server,
            "autoindex on",
        ))
    if _may_serve_php_statically(server):
        findings.append(_server_finding(
            "NGX-DEEP-017",
            Severity.CRITICAL,
            "PHP files may be served statically",
            "The server has PHP entrypoints but no fastcgi location.",
            server,
            "location ~ \\.php$",
        ))
    location_paths: dict[str, list[LocationBlock]] = defaultdict(list)
    for location in server.locations:
        location_paths[location.path].append(location)
        if location.alias and not location.path.endswith("/") and location.alias.endswith("/"):
            findings.append(_location_finding(
                "NGX-DEEP-004",
                Severity.WARNING,
                "root/alias slash mismatch",
                "Alias locations should align trailing slashes with their path.",
                location,
                f"alias {location.alias}",
            ))
        if has_proxy_slash_mismatch(location):
            findings.append(_location_finding(
                "NGX-DEEP-008",
                Severity.INFO,
                "proxy_pass trailing slash mismatch",
                "Location path and proxy_pass disagree on trailing slash handling.",
                location,
                f"proxy_pass {location.proxy_pass}",
            ))
        if location.autoindex:
            findings.append(_location_finding(
                "NGX-DEEP-015",
                Severity.CRITICAL,
                "Nginx autoindex is enabled",
                "Directory listings are enabled for this location.",
                location,
                "autoindex on",
            ))
    for path, locations in location_paths.items():
        if len(locations) > 1:
            findings.append(_location_finding(
                "NGX-DEEP-014",
                Severity.WARNING,
                f"Duplicate location {path}",
                "Multiple locations use the same match expression.",
                locations[1],
                f"location {path}",
            ))
    if server.ssl_enabled and not _http2_enabled(server):
        findings.append(_server_finding(
            "NGX-DEEP-012",
            Severity.WARNING,
            "HTTP/2 is not enabled on HTTPS server",
            "HTTPS server block does not appear to enable HTTP/2.",
            server,
            "listen 443 ssl",
        ))
    return findings


def _server_finding(
    rule_id: str,
    severity: Severity,
    condition: str,
    cause: str,
    server: ServerBlock,
    excerpt: str,
) -> Finding:
    return Finding(
        id=rule_id,
        severity=severity,
        confidence=0.9,
        condition=condition,
        cause=cause,
        evidence=[
            Evidence(server.source_file or "nginx config", server.line_number, excerpt, "nginx -T")
        ],
        treatment="Review and adjust the Nginx server block.",
        impact=["Requests may route incorrectly or expose unsafe behavior."],
    )


def _location_finding(
    rule_id: str,
    severity: Severity,
    condition: str,
    cause: str,
    location: LocationBlock,
    excerpt: str,
) -> Finding:
    return Finding(
        id=rule_id,
        severity=severity,
        confidence=0.85,
        condition=condition,
        cause=cause,
        evidence=[
            Evidence(
                location.source_file or "nginx config",
                location.line_number,
                excerpt,
                "nginx -T",
            )
        ],
        treatment="Review and adjust the Nginx location block.",
        impact=["Requests may route incorrectly or expose unsafe behavior."],
    )


def _project_for_root(model: ServerModel, root: str | None):
    if not root:
        return None
    for project in model.projects:
        if root.startswith(project.path.rstrip("/")):
            return project
    return None


def _looks_like_spa(project) -> bool:
    if not project:
        return False
    return str(getattr(project.type, "value", project.type)) in {"react_spa", "vue_spa"}


def _has_try_files(server: ServerBlock, needle: str) -> bool:
    values = [loc.try_files or "" for loc in server.locations]
    return any(needle in value for value in values)


def _may_serve_php_statically(server: ServerBlock) -> bool:
    if "index.php" not in server.index:
        return False
    return not any(loc.fastcgi_pass for loc in server.locations)


def _http2_enabled(server: ServerBlock) -> bool:
    if server.http2_enabled is True:
        return True
    return any("http2" in listen.lower() for listen in server.listen)
