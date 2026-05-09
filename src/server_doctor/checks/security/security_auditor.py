"""Security Auditor.

Checks for common security misconfigurations and best practices.

Checks:
- SEC-HEAD-1: Missing Security Headers (X-Frame, X-Content, HSTS, etc.)
- NGX-SEC-2: autoindex is enabled (directory listing prevention)
- NGX-SEC-3: Dotfile protection is missing (/.git, .env handling)
- NGX-SEC-4: PHP execution allowed in uploads directory
"""

import re
from dataclasses import dataclass
from fnmatch import fnmatch
from typing import TYPE_CHECKING
from urllib.parse import urlparse

from server_doctor.checks import BaseCheck, CheckContext, register_check
from server_doctor.model.evidence import Evidence, Severity
from server_doctor.model.finding import Finding
from server_doctor.model.server import LocationBlock, ServerBlock, HttpProbeResult

if TYPE_CHECKING:
    from server_doctor.model.server import NginxInfo


@register_check
class SecurityAuditor(BaseCheck):
    """Auditor for security settings."""
    
    @property
    def category(self) -> str:
        return "security"
    
    @property
    def requires_ssh(self) -> bool:
        return False  # Works on parsed model
    
    def run(self, context: CheckContext) -> list[Finding]:
        """Run security checks."""
        self.context = context
        findings: list[Finding] = []
        
        if not context.model.nginx:
            return []
            
        info = context.model.nginx
        findings.extend(self._check_security_headers(info))
        findings.extend(self._check_autoindex(info))
        findings.extend(self._check_dotfile_protection(info))
        findings.extend(self._check_sensitive_paths(info))
        findings.extend(self._check_php_in_uploads(info))
        
        return findings

    def _get_all_locations(self, location: LocationBlock) -> list[LocationBlock]:
        """Recursively get all nested locations."""
        locs = [location]
        for nested in location.locations:
            locs.extend(self._get_all_locations(nested))
        return locs
        
    def _iter_all_locations(self, info: "NginxInfo") -> list[tuple[ServerBlock, LocationBlock]]:
        """Utility to iterate all (server, location) pairs including nested ones."""
        pairs = []
        for server in info.servers:
            for loc in server.locations:
                all_locs = self._get_all_locations(loc)
                for nested in all_locs:
                    pairs.append((server, nested))
        return pairs
    
    def _check_security_headers(self, info: "NginxInfo | None") -> list[Finding]:
        """SEC-HEAD-1: Check for essential security headers with inheritance logic."""
        if not info:
            return []
            
        findings = []
        
        required_headers = {
            "X-Frame-Options": "SAMEORIGIN",
            "X-Content-Type-Options": "nosniff",
            "Referrer-Policy": "no-referrer-when-downgrade",  # or stricter
            # HSTS is special (HTTPS only), processed separately potentially
        }
        
        for server, location in self._iter_all_locations(info):
            # For each location, verify effective headers
            # Determine effective headers for this scope
            effective_headers = self._get_effective_headers(info, server, location)
                
            missing = []
            for name, _ in required_headers.items():
                # Check keys case-insensitively
                if not any(k.lower() == name.lower() for k in effective_headers):
                    missing.append(name)
            
            if missing:
                # Construct nice evidence using inheritance info
                # Show where headers ARE defined to explain why they were lost
                evidence_list = []
                
                # Show definition site of current effective headers
                if location.headers:
                    evidence_list.append(Evidence(
                        source_file=info.config_path, # approximated
                        line_number=location.line_number,
                        excerpt=f"Location '{location.path}' defines add_header, clearing parent headers",
                        command="",
                    ))
                
                findings.append(Finding(
                    id="SEC-HEAD-1",
                    severity=Severity.WARNING,
                    confidence=0.9,
                    condition="Missing security headers",
                    cause=(
                        f"Location '{location.path}' is missing: {', '.join(missing)}. "
                        "Note: Nginx inheritance depends on add_header/add_header_inherit at each level."
                    ),
                    evidence=[Evidence(
                        source_file=server.source_file,
                        line_number=location.line_number,
                        excerpt=f"Location: {location.path}",
                        command="",
                    )] + evidence_list,
                    treatment=(
                        "Add missing headers directly to this block or ensure no `add_header` "
                        "directive overrides parent headers (or use `add_header_inherit merge;`)."
                    ),
                    fix_commands=[
                        f"cat >> {server.source_file or '/etc/nginx/conf.d/security.conf'} << 'EOF'",
                        f"location {location.path} {{",
                        "    add_header X-Frame-Options 'SAMEORIGIN' always;",
                        "    add_header X-Content-Type-Options 'nosniff' always;",
                        "    add_header Referrer-Policy 'strict-origin-when-cross-origin' always;",
                        "}",
                        "EOF",
                        "nginx -t && systemctl reload nginx"
                    ],
                    impact=[
                        "Clickjacking attacks (X-Frame-Options)",
                        "MIME-sniffing attacks (X-Content-Type-Options)",
                        "Information leakage (Referrer-Policy)",
                    ],
                ))
                    
        return findings

    def _get_effective_headers(
        self, info: "NginxInfo", server: ServerBlock, location: LocationBlock
    ) -> dict[str, str]:
        """Calculate effective add_header values including add_header_inherit semantics."""
        http_headers = dict(info.http_headers or {})
        http_mode = self._normalize_add_header_inherit(info.http_add_header_inherit)

        server_headers = dict(server.headers)
        server_inc_headers, server_inc_mode = self._resolve_include_headers(info, server.include_files)
        server_headers.update(server_inc_headers)
        server_mode = self._normalize_add_header_inherit(
            server.add_header_inherit or server_inc_mode or http_mode
        )
        effective_server_headers = self._apply_add_header_inheritance(
            parent_headers=http_headers,
            current_headers=server_headers,
            mode=server_mode,
        )

        location_headers = dict(location.headers)
        loc_inc_headers, loc_inc_mode = self._resolve_include_headers(info, location.include_files)
        location_headers.update(loc_inc_headers)
        location_mode = self._normalize_add_header_inherit(
            location.add_header_inherit or loc_inc_mode or server_mode
        )
        return self._apply_add_header_inheritance(
            parent_headers=effective_server_headers,
            current_headers=location_headers,
            mode=location_mode,
        )

    def _resolve_include_headers(
        self,
        info: "NginxInfo",
        include_specs: list[str],
        visited: set[str] | None = None,
    ) -> tuple[dict[str, str], str | None]:
        """Best-effort parse of add_header and add_header_inherit in included files."""
        if not include_specs:
            return ({}, None)
        if visited is None:
            visited = set()

        headers: dict[str, str] = {}
        inherit_mode: str | None = None

        for include_spec in include_specs:
            for file_path in self._match_include_files(info, include_spec):
                if file_path in visited:
                    continue
                visited.add(file_path)
                content = info.virtual_files.get(file_path, "")
                if not content:
                    continue

                nested_includes: list[str] = []
                for raw_line in content.splitlines():
                    line = raw_line.strip()
                    if not line or line.startswith("#"):
                        continue

                    if line.startswith("add_header "):
                        parts = line.rstrip(";").split(None, 2)
                        if len(parts) >= 3:
                            headers[parts[1]] = parts[2]
                    elif line.startswith("add_header_inherit "):
                        parts = line.rstrip(";").split(None, 1)
                        if len(parts) == 2:
                            inherit_mode = parts[1].strip()
                    elif line.startswith("include "):
                        nested_includes.append(line[len("include "):].rstrip(";").strip())

                if nested_includes:
                    nested_headers, nested_mode = self._resolve_include_headers(info, nested_includes, visited)
                    headers.update(nested_headers)
                    if nested_mode is not None:
                        inherit_mode = nested_mode

        return (headers, inherit_mode)

    @staticmethod
    def _normalize_add_header_inherit(value: str | None) -> str:
        mode = (value or "on").strip().strip(";").strip('"').strip("'").lower()
        return mode if mode in {"on", "off", "merge"} else "on"

    @staticmethod
    def _apply_add_header_inheritance(
        parent_headers: dict[str, str],
        current_headers: dict[str, str],
        mode: str,
    ) -> dict[str, str]:
        """Apply add_header inheritance mode to current scope headers."""
        if mode == "off":
            return dict(current_headers)
        if mode == "merge":
            merged = dict(parent_headers)
            merged.update(current_headers)
            return merged
        # mode == "on" (default)
        return dict(current_headers) if current_headers else dict(parent_headers)

    def _match_include_files(self, info: "NginxInfo", include_spec: str) -> list[str]:
        spec = (include_spec or "").strip().strip('"').strip("'")
        if not spec:
            return []

        all_files = list((info.virtual_files or {}).keys())
        if "*" in spec or "?" in spec or "[" in spec:
            return [path for path in all_files if fnmatch(path, spec)]

        if spec in info.virtual_files:
            return [spec]

        normalized_suffix = "/" + spec.lstrip("./")
        return [path for path in all_files if path.endswith(normalized_suffix)]

    def _check_autoindex(self, info: "NginxInfo | None") -> list[Finding]:
        """NGX-SEC-2: Check for autoindex on."""
        if not info:
            return []
            
        findings = []
        for server in info.servers:
            if server.autoindex:
                findings.append(Finding(
                    id="NGX-SEC-2",
                    severity=Severity.WARNING,
                    confidence=1.0,
                    condition="Directory listing (autoindex) enabled",
                    cause=f"The 'autoindex on;' directive is present in the server block for {server.server_names}.",
                    evidence=[Evidence(
                        source_file=server.source_file,
                        line_number=server.line_number,
                        excerpt="autoindex on;",
                        command="",
                    )],
                    treatment="Disable autoindex: 'autoindex off;' or remove the directive.",
                    fix_commands=[
                        f"sed -i 's/autoindex on;/autoindex off;/g' {server.source_file}",
                        "nginx -t && systemctl reload nginx"
                    ],
                    impact=["Sensitive files in the web root may be disclosed to attackers."],
                ))
        return findings

    def _check_dotfile_protection(self, info: "NginxInfo | None") -> list[Finding]:
        """NGX-SEC-3: Check if dotfiles are blocked."""
        if not info:
            return []
            
        findings = []
        
        for server in info.servers:
            has_dotfile_block = False
            
            for location in server.locations:
                # Look for locations matching /\. or ~ /\\.
                # Common pattern: location ~ /\.
                if r"/\." in location.path or r"\." in location.path:
                    # Check if it denies all
                    # We don't have 'deny all' parsed yet. 
                    # But we can check if a "location ~ /\\. {" exists at all.
                    has_dotfile_block = True
                    break
            
            if not has_dotfile_block:
                proxy_only = self._is_proxy_only_server(server)
                severity = Severity.INFO if proxy_only else Severity.WARNING
                risk_line = (
                    "Server appears proxy-only with minimal direct filesystem exposure."
                    if proxy_only
                    else "Server serves content from filesystem roots/aliases where dotfiles may leak."
                )
                findings.append(Finding(
                    id="NGX-SEC-3",
                    severity=severity,
                    confidence=0.85,
                    condition="Missing dotfile protection",
                    cause=f"Server {server.server_names} has no location block targeting dotfiles. {risk_line}",
                    evidence=[Evidence(
                        source_file=server.source_file,
                        line_number=server.line_number,
                        excerpt="server { ... }",
                        command="",
                    )],
                    treatment=(
                        "Add dotfile protection:\n"
                        "    location ~ /\\. {\n"
                        "        deny all;\n"
                        "    }"
                    ),
                    fix_commands=[
                        f"cat >> {server.source_file or '/etc/nginx/conf.d/security.conf'} << 'EOF'",
                        "location ~ /\\. {",
                        "    deny all;",
                        "    access_log off;",
                        "    log_not_found off;",
                        "}",
                        "EOF",
                        "nginx -t && systemctl reload nginx"
                    ],
                    impact=[
                        "Sensitive files like .env, .git/ may be publicly accessible",
                    ],
                ))
        
        return findings

    def _is_proxy_only_server(self, server: ServerBlock) -> bool:
        """Heuristic: server with no root and only proxy locations."""
        if server.root:
            return False
        if not server.locations:
            return False

        for location in server.locations:
            if location.root or location.alias or location.fastcgi_pass:
                return False
            if not location.proxy_pass:
                return False
        return True

    def _check_sensitive_paths(self, info: "NginxInfo | None") -> list[Finding]:
        """Flag locations serving known sensitive/admin/debug dashboards."""
        if not info:
            return []

        findings: list[Finding] = []
        patterns = [
            r"^/admin", r"^/login", r"phpinfo\.php$", r"/telescope", r"/horizon", r"/debug",
        ]

        probe_map = self._build_probe_path_map(info)

        for server in info.servers:
            for loc in server.locations:
                if self._is_location_access_restricted(info, loc, server):
                    continue
                for pat in patterns:
                    if re.search(pat, loc.path, re.IGNORECASE):
                        severity = Severity.WARNING
                        if server.is_default_server:
                            severity = Severity.CRITICAL

                        probe = probe_map.get(loc.path)
                        if probe is not None:
                            confidence = 0.88
                            excerpt = f"{loc.path} (Probe confirmed: HTTP {probe.status_code})"
                            command = f"curl -I -L --max-redirs 5 {probe.url}"
                        else:
                            confidence = 0.55
                            excerpt = f"{loc.path} (Route exists in Nginx config, not probed)"
                            command = "nginx -T"

                        findings.append(Finding(
                            id="NGX-SENS-1",
                            severity=severity,
                            confidence=confidence,
                            condition=f"Sensitive path '{loc.path}' exposed",
                            cause=(
                                f"Location '{loc.path}' matches sensitive pattern '{pat}' in server {server.server_names}."
                            ),
                            evidence=[Evidence(
                                source_file=loc.source_file or server.source_file or info.config_path,
                                line_number=loc.line_number or server.line_number or 1,
                                excerpt=excerpt,
                                command=command,
                            )],
                            treatment=(
                                "Restrict access to this path (authentication, IP allowlist, remove if unused)."
                            ),
                            impact=[
                                "Administrative or debug interface reachable from clients",
                            ],
                        ))
                        break
        return findings

    def _build_probe_path_map(self, info: "NginxInfo") -> dict[str, HttpProbeResult]:
        """Build a dict mapping URL paths -> probe results for quick lookup."""
        if not hasattr(self, "context") or not self.context:
            return {}
        model = self.context.model
        if not model or not model.http_probes:
            return {}
        probe_map: dict[str, HttpProbeResult] = {}
        for result in model.http_probes.results:
            path = urlparse(result.url).path.rstrip("/") or "/"
            probe_map[path] = result
        return probe_map

    def _is_location_access_restricted(
        self,
        info: "NginxInfo",
        location: LocationBlock,
        server: ServerBlock | None = None,
    ) -> bool:
        """Treat deny-all with allowlist as non-public, including inherited server rules."""
        loc_allow = list(location.allow_rules)
        loc_deny = list(location.deny_rules)
        loc_auth = location.auth_basic
        loc_inc_allow, loc_inc_deny, loc_inc_auth = self._resolve_include_access_rules(info, location.include_files)
        loc_allow.extend(loc_inc_allow)
        loc_deny.extend(loc_inc_deny)
        if loc_auth is None:
            loc_auth = loc_inc_auth
        srv_auth: str | None = None

        if loc_allow or loc_deny:
            allow_rules = loc_allow
            deny_rules = loc_deny
        elif server:
            srv_allow = list(server.allow_rules)
            srv_deny = list(server.deny_rules)
            srv_auth = server.auth_basic
            srv_inc_allow, srv_inc_deny, srv_inc_auth = self._resolve_include_access_rules(info, server.include_files)
            srv_allow.extend(srv_inc_allow)
            srv_deny.extend(srv_inc_deny)
            if srv_auth is None:
                srv_auth = srv_inc_auth
            allow_rules = srv_allow
            deny_rules = srv_deny
        else:
            allow_rules = []
            deny_rules = []
            srv_auth = None

        deny_values = {rule.strip().lower() for rule in deny_rules}
        allow_values = {rule.strip().lower() for rule in allow_rules}

        deny_all = "all" in deny_values
        allow_all = "all" in allow_values

        # auth_basic in scope means location is not publicly exposed without authentication.
        effective_auth = loc_auth if loc_auth is not None else srv_auth
        if effective_auth and effective_auth.strip().lower() != "off":
            return True

        # Explicit deny/forbidden return blocks should not be treated as exposed.
        if location.return_directive:
            first_token = location.return_directive.split()[0].strip()
            if first_token in {"401", "403", "404", "410", "444"}:
                return True

        # deny all + any non-wildcard allowlist is considered restricted.
        return deny_all and not allow_all

    def _resolve_include_access_rules(
        self,
        info: "NginxInfo",
        include_specs: list[str],
        visited: set[str] | None = None,
    ) -> tuple[list[str], list[str], str | None]:
        """Best-effort parse of allow/deny/auth_basic rules from included files."""
        if not include_specs:
            return ([], [], None)
        if visited is None:
            visited = set()

        allow_rules: list[str] = []
        deny_rules: list[str] = []
        auth_basic: str | None = None

        for include_spec in include_specs:
            for file_path in self._match_include_files(info, include_spec):
                if file_path in visited:
                    continue
                visited.add(file_path)
                content = info.virtual_files.get(file_path, "")
                if not content:
                    continue

                nested_includes: list[str] = []
                for raw_line in content.splitlines():
                    line = raw_line.strip()
                    if not line or line.startswith("#"):
                        continue

                    if line.startswith("allow "):
                        value = line[len("allow "):].rstrip(";").strip()
                        if value:
                            allow_rules.append(value)
                    elif line.startswith("deny "):
                        value = line[len("deny "):].rstrip(";").strip()
                        if value:
                            deny_rules.append(value)
                    elif line.startswith("auth_basic "):
                        value = line[len("auth_basic "):].rstrip(";").strip()
                        if value:
                            auth_basic = value
                    elif line.startswith("include "):
                        nested_includes.append(line[len("include "):].rstrip(";").strip())

                if nested_includes:
                    nested_allow, nested_deny, nested_auth = self._resolve_include_access_rules(
                        info,
                        nested_includes,
                        visited,
                    )
                    allow_rules.extend(nested_allow)
                    deny_rules.extend(nested_deny)
                    if nested_auth is not None:
                        auth_basic = nested_auth

        return (allow_rules, deny_rules, auth_basic)

    def _check_php_in_uploads(self, info: "NginxInfo | None") -> list[Finding]:
        """NGX-SEC-4: Check if PHP execution is supposedly blocked in uploads."""
        if not info:
            return []
            
        findings = []
        risky_keywords = ["upload", "storage", "public/media", "wp-content/uploads"]
        
        def check_recursive(location: LocationBlock, in_uploads: bool):
            current_is_uploads = in_uploads or any(k in location.path for k in risky_keywords)
            
            if current_is_uploads and location.fastcgi_pass:
                findings.append(Finding(
                    id="NGX-SEC-4",
                    severity=Severity.CRITICAL,
                    confidence=0.95,
                    condition="PHP execution enabled in uploads directory",
                    cause=f"Location '{location.path}' contains fastcgi_pass directive.",
                    evidence=[Evidence(
                        source_file=info.config_path, 
                        line_number=location.line_number,
                        excerpt=f"fastcgi_pass {location.fastcgi_pass}",
                        command="",
                    )],
                    treatment=(
                        "Remove PHP execution from upload directories.\n"
                        "Ensure: location ... { try_files $uri =404; }"
                    ),
                    fix_commands=[
                        f"# Edit {location.source_file or info.config_path} and remove fastcgi_pass from {location.path}",
                        f"# Replace with: try_files $uri =404;",
                        "nginx -t && systemctl reload nginx"
                    ],
                    impact=[
                        "Malicious PHP scripts uploaded by users can be executed",
                        "Full server compromise (webshell risks)",
                    ],
                ))
            
            for nested in location.locations:
                check_recursive(nested, current_is_uploads)

        for server in info.servers:
            for location in server.locations:
                check_recursive(location, False)
                    
        return findings
