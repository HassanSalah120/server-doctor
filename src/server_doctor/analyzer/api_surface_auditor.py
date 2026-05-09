"""API Surface Auditor - Detects exposed sensitive endpoints and info disclosure.

Only publicly-routable endpoints (public domain/IP) produce critical findings.
localhost/private/internal exposures are tagged as internal-only findings.
"""

import re
from urllib.parse import urlparse

from server_doctor.model.evidence import Evidence, Severity
from server_doctor.model.finding import Finding
from server_doctor.model.server import ServerModel

_SENSITIVE_API_PATHS = frozenset({
    "/graphql", "/graphiql", "/graphql/explore",
    "/api/graphql", "/api/v1/graphql",
    "/swagger.json", "/swagger.yaml", "/api-docs", "/docs",
    "/openapi.json", "/v2/api-docs", "/api/swagger",
    "/debug", "/debugbar", "/_debugbar",
    "/telescope", "/telescope/requests",
    "/admin", "/administrator", "/wp-admin",
    "/backup", "/backup.sql", "/dump.sql",
    "/.git/config", "/.git/HEAD",
    "/composer.json", "/package.json",
    "/.env", "/.env.example",
})

_STACK_TRACE_PATTERNS: list[re.Pattern] = [
    re.compile(r"#\d+\s+\S+\.php\(|Stack trace:|PHP Fatal error|Fatal error:.*?in /"),
    re.compile(r"at\s+\S+\.java:\d+|java\.lang\.\w+Exception|Caused by: java\.lang\."),
    re.compile(r"File\s+\"/var/www|File\s+\"/srv|in\s+/var/www|in\s+/srv"),
    re.compile(r"Traceback \(most recent call last\):|File \"/usr/lib/python"),
    re.compile(r"Error:\s+.*?in\s+/var/www|Warning:\s+.*?in\s+/var/www"),
]

_PRIVATE_HOSTS = frozenset({
    "localhost", "127.0.0.1", "::1", "0.0.0.0",
})

_PRIVATE_PREFIXES = ("10.", "172.16.", "172.17.", "172.18.", "172.19.",
                     "172.20.", "172.21.", "172.22.", "172.23.", "172.24.",
                     "172.25.", "172.26.", "172.27.", "172.28.", "172.29.",
                     "172.30.", "172.31.", "192.168.",)


def _normalize_url(url: str) -> str:
    """Normalize a URL for deduplication: lowercase, strip fragment, normalize slash."""
    parsed = urlparse(url)
    scheme = parsed.scheme.lower()
    host = parsed.hostname.lower() if parsed.hostname else ""
    port = parsed.port
    path = parsed.path.rstrip("/") or "/"
    if port and port == (443 if scheme == "https" else 80):
        port = None
    netloc = f"{host}:{port}" if port else host
    return f"{scheme}://{netloc}{path}"


def _classify_host(host: str) -> str:
    """Classify a host into exposure scope categories."""
    host_lower = host.lower().strip()
    if host_lower in _PRIVATE_HOSTS:
        return "localhost"
    if host_lower.startswith(_PRIVATE_PREFIXES):
        return "private_ip"
    # Check if it looks like an IP address
    parts = host_lower.split(".")
    if len(parts) == 4 and all(p.isdigit() for p in parts):
        return "public_ip"
    # Has dots but not an IP -> likely a domain name
    if "." in host_lower:
        return "public_domain"
    # Single-name host like "localhost" (already caught) or docker container
    return "internal_docker"


class ApiSurfaceAuditor:
    """Auditor that detects exposed sensitive endpoints and stack trace disclosure."""

    def __init__(self, model: ServerModel) -> None:
        self.model = model

    def audit(self) -> list[Finding]:
        findings: list[Finding] = []
        if not self.model.http_probes or not self.model.http_probes.results:
            return findings

        findings.extend(self._find_exposed_sensitive_paths())
        findings.extend(self._find_stack_traces_in_responses())
        return findings

    def _normalized_results(self):
        """Yield (normalized_url, classification_scope, original_result) for each probe, deduplicated by normalized URL."""
        seen: set[str] = set()
        for r in self.model.http_probes.results:
            norm = _normalize_url(r.url)
            if norm in seen:
                continue
            seen.add(norm)
            parsed = urlparse(r.url)
            host = parsed.hostname or ""
            scope = _classify_host(host)
            yield norm, scope, r

    def _find_exposed_sensitive_paths(self) -> list[Finding]:
        public_exposed: list[tuple[str, str, str]] = []  # (normalized_url, scope, path)
        internal_exposed: list[tuple[str, str, str]] = []
        all_exposed: list[tuple[str, str, str, str]] = []  # (norm_url, scope, path, rule_id)

        for norm_url, scope, r in self._normalized_results():
            path = urlparse(norm_url).path.rstrip("/") or "/"
            if path not in _SENSITIVE_API_PATHS:
                continue
            if r.status_code in {401, 403, 404}:
                continue

            all_exposed.append((norm_url, scope, path, r.url))
            if scope in ("public_domain", "public_ip"):
                public_exposed.append((norm_url, scope, path))
            else:
                internal_exposed.append((norm_url, scope, path))

        findings: list[Finding] = []

        # Public exposure findings (only for public_domain/public_ip)
        if public_exposed:
            unique_paths = sorted(set(p for _, _, p in public_exposed))
            url_variants = sorted(set(u for u, _, _ in public_exposed))
            schemes = sorted(set(u.split(":")[0] for u in url_variants))
            hosts = sorted(set(u.split("/")[2] for u in url_variants))
            findings.append(Finding(
                id="API-001",
                severity=Severity.WARNING,
                confidence=0.85,
                condition=f"{len(unique_paths)} sensitive path(s) publicly accessible, {len(url_variants)} URL variant(s)",
                cause=f"Paths: {', '.join(unique_paths[:8])}. Schemes: {', '.join(schemes)}. Hosts: {', '.join(hosts[:3])}.",
                evidence=[Evidence(
                    source_file="http probe",
                    line_number=0,
                    excerpt=f"Paths: {', '.join(unique_paths[:8])}. URL variants: {', '.join(url_variants[:8])}",
                    command="curl -I -L " + url_variants[0],
                )],
                treatment="Restrict access to sensitive endpoints with authentication or IP allowlisting.",
                impact=[
                    "Attackers can discover API structure and sensitive functionality",
                    "Higher risk of data breach or privilege escalation",
                ],
            ))

        # Internal-only exposure (localhost/private) — info/warning, not critical
        if internal_exposed:
            unique_paths = sorted(set(p for _, _, p in internal_exposed))
            url_variants = sorted(set(u for u, _, _ in internal_exposed))
            schemes = sorted(set(u.split(":")[0] for u in url_variants))
            severities = {s for _, s, _ in internal_exposed}
            sev = Severity.WARNING if "internal_docker" in severities else Severity.INFO
            findings.append(Finding(
                id="API-001",
                severity=sev,
                confidence=0.70,
                condition=f"{len(unique_paths)} sensitive path(s) exposed on internal/local host, {len(url_variants)} URL variant(s)",
                cause=f"Internal paths: {', '.join(unique_paths[:8])}. Schemes: {', '.join(schemes)}.",
                evidence=[Evidence(
                    source_file="http probe",
                    line_number=0,
                    excerpt=f"Internal paths: {', '.join(unique_paths[:8])}. URL variants: {', '.join(url_variants[:4])}",
                    command="curl -I -L " + url_variants[0],
                )],
                treatment="Verify these endpoints are not reachable from the public internet.",
                impact=[
                    "Local/internal exposure is lower risk but should still be reviewed",
                ],
            ))

        graphql_public = [(u, p) for u, s, p in public_exposed if "/graphql" in p]
        if graphql_public:
            urls = [u for u, _ in graphql_public]
            findings.append(Finding(
                id="API-002",
                severity=Severity.WARNING,
                confidence=0.90,
                condition="GraphQL endpoint is publicly accessible",
                cause=f"GraphQL accessible at {', '.join(urls[:3])}",
                evidence=[Evidence(
                    source_file="http probe",
                    line_number=0,
                    excerpt=f"GraphQL exposed: {', '.join(urls[:3])}",
                    command="curl -I -L " + urls[0],
                )],
                treatment="Add authentication to GraphQL endpoint and disable introspection in production.",
                impact=[
                    "GraphQL schema and data can be queried without authentication",
                    "Introspection queries can reveal entire data model",
                ],
            ))

        debug_public = [(u, p) for u, s, p in public_exposed if any(d in p for d in ("/debug", "/telescope"))]
        if debug_public:
            urls = [u for u, _ in debug_public]
            findings.append(Finding(
                id="API-003",
                severity=Severity.CRITICAL,
                confidence=0.95,
                condition="Debug/telescope panel is publicly accessible",
                cause=f"Debug panel accessible at {', '.join(urls[:3])}",
                evidence=[Evidence(
                    source_file="http probe",
                    line_number=0,
                    excerpt=f"Debug exposed: {', '.join(urls[:3])}",
                    command="curl -I -L " + urls[0],
                )],
                treatment="Disable debug mode in production and restrict access to debug panels.",
                impact=[
                    "Full application state and queries visible to attackers",
                    "Environment variables and secrets may be exposed",
                ],
            ))

        backup_public = [(u, p) for u, s, p in public_exposed if any(b in p for b in ("/backup", "/dump"))]
        if backup_public:
            urls = [u for u, _ in backup_public]
            findings.append(Finding(
                id="API-004",
                severity=Severity.CRITICAL,
                confidence=0.95,
                condition="Backup/dump file is publicly accessible",
                cause=f"Backup file accessible at {', '.join(urls[:3])}",
                evidence=[Evidence(
                    source_file="http probe",
                    line_number=0,
                    excerpt=f"Backup exposed: {', '.join(urls[:3])}",
                    command="curl -I -L " + urls[0],
                )],
                treatment="Move backup files outside the web root and block access to /backup paths.",
                impact=[
                    "Database dumps and application code may be downloaded",
                    "Critical data breach risk",
                ],
            ))

        vcs_public = [(u, p) for u, s, p in public_exposed if ".git" in p]
        if vcs_public:
            urls = (u for u, _ in vcs_public)
            findings.append(Finding(
                id="API-005",
                severity=Severity.CRITICAL,
                confidence=0.95,
                condition="Git metadata is publicly accessible",
                cause=f"VCS exposed on public domain/IP: {', '.join(urls[:3])}",
                evidence=[Evidence(
                    source_file="http probe",
                    line_number=0,
                    excerpt=f"Git exposed on public host: {', '.join(urls[:3])}",
                    command="curl -I -L " + urls[0],
                )],
                treatment="Block .git paths in Nginx and remove .git directories from web root.",
                impact=[
                    "Full source code and commit history can be downloaded",
                    "Credentials in git history may be compromised",
                ],
            ))

        return findings

    def _find_stack_traces_in_responses(self) -> list[Finding]:
        trace_findings: list[Finding] = []
        for norm_url, scope, r in self._normalized_results():
            body = r.body_sample or ""
            if not body:
                continue
            matches = []
            for pat in _STACK_TRACE_PATTERNS:
                if pat.search(body):
                    matches.append(pat.pattern[:60])
            if matches:
                severity = Severity.WARNING if scope in ("public_domain", "public_ip") else Severity.INFO
                trace_findings.append(Finding(
                    id="API-006",
                    severity=severity,
                    confidence=0.90,
                    condition="Stack trace detected in HTTP response body",
                    cause=f"{norm_url} response body contains stack trace pattern(s): {', '.join(matches[:3])}",
                    evidence=[Evidence(
                        source_file="http probe",
                        line_number=0,
                        excerpt=f"Stack trace in response from {norm_url} (scope={scope})",
                        command=f"curl -s {r.url} | head -100",
                    )],
                    treatment="Disable debug/display_errors in production and configure proper error logging.",
                    impact=[
                        "Source code paths and application internals visible to users",
                        "Facilitates targeted attacks",
                    ],
                ))
        return trace_findings
