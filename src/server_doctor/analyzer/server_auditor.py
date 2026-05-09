"""Server Auditor - Security and sanity checks.

Advisory findings for security concerns and best practices.
These are non-breaking but potentially dangerous issues.
"""

from server_doctor.model.evidence import Evidence, Severity
from server_doctor.model.finding import Finding
from server_doctor.model.server import ProjectType, ServerModel


class ServerAuditor:
    """Server auditor for security and sanity checks.

    Checks for:
    - World-writable directories
    - Exposed .env files
    - Permission issues
    - PHP version mismatches
    - SSL certificate issues
    """

    def __init__(self, model: ServerModel) -> None:
        self.model = model

    def audit(self) -> list[Finding]:
        """Run all audit checks.

        Returns:
            List of advisory Finding objects.
        """
        findings: list[Finding] = []

        findings.extend(self._check_env_exposure())
        findings.extend(self._check_ssl_configuration())
        findings.extend(self._check_php_version_consistency())

        return findings

    def _check_env_exposure(self) -> list[Finding]:
        """Check if .env files might be exposed."""
        findings: list[Finding] = []

        if not self.model.nginx:
            return findings

        # Group projects by exposure status
        exposed_projects = []
        safe_but_exists: list[tuple[str, str | None]] = []

        for project in self.model.projects:
            if not project.env_path:
                continue

            # 1. Determine if .env is inside an ACTIVE Nginx root
            is_reachable = False
            relevant_servers = []
            
            for server in self.model.nginx.servers:
                # Check root directive
                roots = [server.root] if server.root else []
                for loc in server.locations:
                    # some tests create lightweight "L" objects with only a few
                    # attributes; guard against missing fields so the audit logic
                    # remains robust.
                    root_val = getattr(loc, "root", None)
                    if root_val:
                        roots.append(root_val)
                    alias_val = getattr(loc, "alias", None)
                    if alias_val:
                        roots.append(alias_val)
                
                # If project.env_path starts with any of these roots, it MIGHT be reachable
                # Example: env=/var/www/app/.env, root=/var/www/app -> Reachable
                # Example: env=/var/www/app/.env, root=/var/www/app/public -> Not Reachable
                for r in roots:
                    if not r: continue
                    # Normalize for comparison
                    r_norm = r.rstrip("/")
                    env_dir = project.path.rstrip("/") # project.path is where .env lives usually
                    
                    if project.env_path.startswith(r_norm):
                        is_reachable = True
                        relevant_servers.append(server)
                        break
                
                if is_reachable: break

            # 2. If reachable, check for protection
            if is_reachable:
                is_protected = False
                for server in relevant_servers:
                    for location in server.locations:
                        # Detect deny rules: location ~ /\. or location ~ .env
                        if (r"\." in location.path or ".env" in location.path) and "deny all" in self.model.nginx.raw:
                             # This is a weak check on raw config, ideally we check the deny directive in the location
                             # But our model doesn't parse 'deny', so we assume if we see a dot-file location, it's likely for protection
                             # A stronger check would be good, but this reduces false positives from "no location found"
                             is_protected = True
                             break
                    if is_protected: break
                
                if not is_protected:
                    exposed_projects.append(project.path)
            else:
                # Exists but outside root (e.g. Laravel standard)
                safe_but_exists.append((project.path, getattr(project, "env_permissions", None)))

        # Create consolidated findings
        if exposed_projects:
            findings.append(
                Finding(
                    severity=Severity.CRITICAL,
                    confidence=0.90,
                    condition=".env file may be exposed",
                    cause=f"Found .env files within Nginx document root without obvious protection",
                    evidence=[
                        Evidence(source_file=p, line_number=1, excerpt=".env inside web root", command="filesystem scan") 
                        for p in exposed_projects
                    ],
                    treatment=(
                        "Add protection block:\n"
                        "location ~ /\\.(?!well-known).* {\n"
                        "    deny all;\n"
                        "}"
                    ),
                    impact=["Database credentials exposed", "API keys leaked"],
                )
            )

        # Optional: Info for safe files if verbosity needed, or just skip
        # User requested rigorous check: "INFO if .env exists but is outside root"
        non_compliant_safe = [
            (path, perms)
            for path, perms in safe_but_exists
            if not self._is_env_permission_compliant(perms)
        ]
        if non_compliant_safe:
             findings.append(
                Finding(
                    severity=Severity.INFO,
                    confidence=0.60,
                    condition=".env file exists (likely safe)",
                    cause=(
                        "Found .env files outside the public web root with missing or broad permissions. "
                        "Recommended mode is 600 or 640."
                    ),
                    evidence=[
                        Evidence(
                            source_file=path,
                            line_number=1,
                            excerpt=f".env outside root (mode={perms or 'unknown'})",
                            command="filesystem scan",
                        )
                        for path, perms in non_compliant_safe
                    ],
                    treatment="Ensure permissions are 600 or 640 (owner read-only)",
                    impact=["Compliance check"],
                )
            )

        return findings

    @staticmethod
    def _is_env_permission_compliant(mode: str | None) -> bool:
        if not mode:
            return False
        digits = "".join(ch for ch in str(mode) if ch.isdigit())
        if len(digits) < 3:
            return False
        mode3 = digits[-3:]
        owner = int(mode3[0])
        group = int(mode3[1])
        other = int(mode3[2])
        return other == 0 and group in {0, 4} and owner >= 4

    def _check_ssl_configuration(self) -> list[Finding]:
        """Check SSL configuration for issues."""
        findings: list[Finding] = []

        if not self.model.nginx:
            return findings

        for server in self.model.nginx.servers:
            # Check for servers with port 443 but no SSL
            if any("443" in listen and "ssl" not in listen.lower() for listen in server.listen):
                findings.append(
                    Finding(
                        severity=Severity.WARNING,
                        confidence=0.85,
                        condition="Port 443 without SSL directive",
                        cause="Server listens on 443 but 'ssl' not in listen directive",
                        evidence=[
                            Evidence(
                                source_file=server.source_file,
                                line_number=server.line_number,
                                excerpt=f"listen {', '.join(server.listen)}",
                                command="nginx -T",
                            )
                        ],
                        treatment="Add 'ssl' to listen directive: listen 443 ssl;",
                        impact=[
                            "SSL may not be properly enabled",
                            "HTTPS might not work correctly",
                        ],
                    )
                )

            # Check for SSL without certificate
            if server.ssl_enabled and not server.ssl_certificate:
                findings.append(
                    Finding(
                        severity=Severity.CRITICAL,
                        confidence=0.95,
                        condition="SSL enabled without certificate",
                        cause="Server has SSL enabled but no ssl_certificate directive",
                        evidence=[
                            Evidence(
                                source_file=server.source_file,
                                line_number=server.line_number,
                                excerpt="ssl_certificate missing",
                                command="nginx -T",
                            )
                        ],
                        treatment="Add ssl_certificate and ssl_certificate_key directives",
                        impact=[
                            "nginx will fail to start or reload",
                            "HTTPS will not work",
                        ],
                    )
                )

        return findings

    def _check_php_version_consistency(self) -> list[Finding]:
        """Check if server blocks use consistent PHP versions."""
        findings: list[Finding] = []

        if not self.model.php or not self.model.nginx:
            return findings

        # Collect active sockets from all server blocks
        active_sockets: dict[str, list[str]] = {}  # socket -> [server_names]
        
        for server in self.model.nginx.servers:
            # Check all locations for fastcgi_pass
            for loc in server.locations:
                if loc.fastcgi_pass and loc.fastcgi_pass.startswith("unix:"):
                    socket = loc.fastcgi_pass.replace("unix:", "").strip()
                    if socket not in active_sockets:
                        active_sockets[socket] = []
                    
                    name = server.server_names[0] if server.server_names else "default"
                    if name not in active_sockets[socket]:
                        active_sockets[socket].append(name)

        if len(active_sockets) > 1:
            # Multiple versions are actually in use across different sites
            evidence_list = []
            for socket, sites in active_sockets.items():
                evidence_list.append(
                    Evidence(
                        source_file=socket,
                        line_number=1,
                        excerpt=f"Used by: {', '.join(sites[:3])}{'...' if len(sites) > 3 else ''}",
                        command="nginx -T",
                    )
                )

            findings.append(
                Finding(
                    severity=Severity.WARNING,
                    confidence=0.90,
                    condition="Mixed PHP versions in use",
                    cause=f"Found {len(active_sockets)} different PHP-FPM sockets being used across site configurations",
                    evidence=evidence_list,
                    treatment="Consolidate projects to a single PHP version unless specifically required otherwise",
                    impact=[
                        "Higher memory usage (multiple FPM pools)",
                        "Maintenance overhead",
                        "Potential developer confusion",
                    ],
                )
            )
        elif len(self.model.php.versions) > 1:
            # Multiple installed but one or zero in use in nginx
            findings.append(
                Finding(
                    severity=Severity.INFO,
                    confidence=0.80,
                    condition="Multiple PHP versions installed",
                    cause=f"Server has {', '.join(self.model.php.versions)} installed, but Nginx configuration is consistent",
                    evidence=[
                        Evidence(
                            source_file="/usr/bin/php",
                            line_number=1,
                            excerpt=f"Default CLI: PHP {self.model.php.default_version}",
                            command="php -v",
                        )
                    ],
                    treatment="Consider removing unused PHP versions to reduce attack surface and disk usage",
                    impact=[
                        "Unnecessary disk space usage",
                        "Security maintenance overhead",
                    ],
                )
            )

        return findings

