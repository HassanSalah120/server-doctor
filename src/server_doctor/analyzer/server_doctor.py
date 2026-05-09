"""Server Doctor Analyzer - Diagnoses nginx configuration problems.

This is the core diagnostic engine that identifies misconfigurations
and generates evidence-based findings.

IMPORTANT: All findings MUST include evidence with:
- source_file
- line_number  
- excerpt
"""

import re
from typing import TYPE_CHECKING

from server_doctor.model.evidence import Evidence, Severity
from server_doctor.model.finding import Finding
from server_doctor.model.server import (
    NginxInfo,
    ProjectInfo,
    ProjectType,
    ServerBlock,
    ServerModel,
)

if TYPE_CHECKING:
    from server_doctor.model.server import LocationBlock


class ServerDoctorAnalyzer:
    """Diagnoses nginx configuration problems.

    This analyzer NEVER runs shell commands.
    It only reasons about the ServerModel built by scanners and parsers.
    """

    def __init__(self, model: ServerModel, raw_config: str = "") -> None:
        """Initialize with a server model.

        Args:
            model: The complete server model.
            raw_config: Raw nginx -T output for evidence extraction.
        """
        self.model = model
        self.raw_config = raw_config

    def diagnose(self, additional_findings: list[Finding] | None = None) -> list[Finding]:
        """Run all diagnostic checks and group related findings."""
        findings: list[Finding] = []
        if additional_findings:
            findings.extend(additional_findings)

        if not self.model.nginx:
            return findings

        # 1. Run each diagnostic check
        findings.extend(self._check_backup_configs())
        findings.extend(self._check_laravel_roots())
        findings.extend(self._check_dynamic_nginx_paths())
        findings.extend(self._check_missing_try_files())
        findings.extend(self._check_php_socket_mismatch())
        findings.extend(self._check_duplicate_server_names())
        findings.extend(self._check_path_routing_conflicts())
        findings.extend(self._check_default_sites_enabled())
        findings.extend(self._check_php_version_consistency())
        
        # 2. Use centralized deduplication
        from server_doctor.engine.deduplication import deduplicate_findings
        return deduplicate_findings(findings)

    def _check_php_version_consistency(self) -> list[Finding]:
        """Check if multiple PHP versions are installed when only one might be needed."""
        findings: list[Finding] = []
        if not self.model.php or len(self.model.php.versions) <= 1:
            return findings
            
        findings.append(
            Finding(
                severity=Severity.INFO,
                confidence=0.8,
                condition="Multiple PHP versions installed",
                cause=f"Server has {', '.join(self.model.php.versions)} installed",
                evidence=[Evidence(source_file="/usr/bin/php", line_number=1, excerpt=f"Default CLI: PHP {self.model.php.versions[0]}", command="php -v")],
                treatment="Consider removing unused PHP versions to reduce attack surface and disk usage",
                impact=["Unnecessary disk space usage", "Security maintenance overhead"]
            )
        )
        return findings

    def _check_dynamic_nginx_paths(self) -> list[Finding]:
        """Identify Nginx variables or regex captures in config directives.
        
        These are often mistaken for filesystem paths but are actually 
        dynamic variables (e.g., $1, $host).
        """
        findings: list[Finding] = []
        if not self.model.nginx or not self.model.nginx.skipped_paths:
            return findings

        findings.append(
            Finding(
                severity=Severity.INFO,
                confidence=1.0,
                condition="Nginx config variables detected in roots",
                cause=(
                    "Nginx 'root' or 'alias' directives contain dynamic variables or regex captures "
                    "(e.g., $1, $domain). These are not real filesystem paths."
                ),
                evidence=[
                    Evidence(
                        source_file="nginx.conf",
                        line_number=1,
                        excerpt=path,
                        command="nginx -T",
                    )
                    for path in self.model.nginx.skipped_paths
                ],
                treatment=(
                    "These are not real filesystem paths; they appear to be regex capture references "
                    "(e.g., rewrite $1). server-doctor ignores them and avoids treating them as project roots."
                ),
                impact=[
                    "Scanner avoids scanning non-existent dynamic directories",
                    "Cleaner project discovery results",
                ],
            )
        )

        return findings

    def _check_laravel_roots(self) -> list[Finding]:
        """Check if Laravel projects have correct root pointing to /public."""
        findings: list[Finding] = []

        if not self.model.nginx:
            return findings

        # Get Laravel projects
        laravel_projects = [
            p for p in self.model.projects if p.type == ProjectType.LARAVEL
        ]

        for project in laravel_projects:
            expected_root = project.public_path or f"{project.path}/public"

            # Find server blocks that might be for this project
            for server in self.model.nginx.servers:
                if not server.root:
                    continue

                # Check if this server is for this project
                if project.path in server.root and "/public" not in server.root:
                    # Root is pointing to project root, not public
                    findings.append(
                        Finding(
                            severity=Severity.CRITICAL,
                            confidence=0.95,
                            condition="Laravel root misconfigured",
                            cause=f"root points to '{server.root}' instead of '{expected_root}'",
                            evidence=[
                                Evidence(
                                    source_file=server.source_file,
                                    line_number=server.line_number,
                                    excerpt=f"root {server.root}",
                                    command="nginx -T",
                                )
                            ],
                            treatment=f"Change root to '{expected_root}'",
                            impact=[
                                "Assets may fail to load",
                                "Sensitive files may be exposed",
                                "Laravel routing will break",
                            ],
                        )
                    )

        return findings

    def _check_missing_try_files(self) -> list[Finding]:
        """Check for PHP locations missing try_files directive."""
        findings: list[Finding] = []

        if not self.model.nginx:
            return findings

        for server in self.model.nginx.servers:
            for location in server.locations:
                # Check if this is a PHP location
                if location.fastcgi_pass and not location.try_files:
                    findings.append(
                        Finding(
                            severity=Severity.WARNING,
                            confidence=0.85,
                            condition="Missing try_files in PHP location",
                            cause="PHP location has no try_files fallback for routing",
                            evidence=[
                                Evidence(
                                    source_file=server.source_file,
                                    line_number=location.line_number,
                                    excerpt=f"location {location.path}",
                                    command="nginx -T",
                                )
                            ],
                            treatment="Add: try_files $uri $uri/ /index.php?$query_string;",
                            impact=[
                                "Pretty URLs may not work",
                                "Framework routing may fail",
                            ],
                        )
                    )

        return findings

    def _check_php_socket_mismatch(self) -> list[Finding]:
        """Check if fastcgi_pass points to existing PHP-FPM sockets."""
        findings: list[Finding] = []

        if not self.model.nginx or not self.model.php:
            return findings

        available_sockets = set(self.model.php.sockets)

        for server in self.model.nginx.servers:
            for location in server.locations:
                if not location.fastcgi_pass:
                    continue

                # Check if it's a unix socket
                if location.fastcgi_pass.startswith("unix:"):
                    socket_path = location.fastcgi_pass.replace("unix:", "").strip()
                    if socket_path not in available_sockets:
                        findings.append(
                            Finding(
                                severity=Severity.CRITICAL,
                                confidence=0.90,
                                condition="PHP-FPM socket not found",
                                cause=f"fastcgi_pass points to '{socket_path}' which doesn't exist",
                                evidence=[
                                    Evidence(
                                        source_file=server.source_file,
                                        line_number=location.line_number,
                                        excerpt=f"fastcgi_pass {location.fastcgi_pass}",
                                        command="nginx -T",
                                    )
                                ],
                                treatment=f"Update to an available socket: {', '.join(available_sockets) or 'none found'}",
                                impact=[
                                    "PHP will not work at all",
                                    "502 Bad Gateway errors",
                                ],
                            )
                        )

        return findings

    def _check_duplicate_server_names(self) -> list[Finding]:
        """Check for duplicate server_name declarations.
        
        Groups all occurrences of the same name into a single finding.
        """
        findings: list[Finding] = []

        if not self.model.nginx:
            return findings

        # Collect all server blocks per server_name
        name_to_servers: dict[str, list[ServerBlock]] = {}
        
        for server in self.model.nginx.servers:
            for name in server.server_names:
                if name not in name_to_servers:
                    name_to_servers[name] = []
                name_to_servers[name].append(server)

        # Create one finding per duplicated name (with all occurrences as evidence)
        for name, servers in name_to_servers.items():
            if len(servers) <= 1:
                continue  # Not a duplicate
            if not self._has_overlapping_listens(servers):
                # Same server_name on different listen sockets (e.g. :80 and :443) is expected.
                continue

            winner = self._simulate_routing_winner(servers)
            winner_ref = f"{winner.source_file}:{winner.line_number}" if winner else "unknown"
            shadowed_count = len(servers) - (1 if winner else 0)
            impact = self._duplicate_server_effective_impact(winner, [s for s in servers if s is not winner])
            severity = impact["severity"]
            env_split = self._is_prod_local_split_duplicate(servers)
            
            evidence_list = [
                Evidence(
                    source_file=s.source_file,
                    line_number=s.line_number,
                    excerpt=f"server_name {' '.join(s.server_names)}",
                    command="nginx -T",
                )
                for s in servers
            ]
            if winner:
                evidence_list.append(
                    Evidence(
                        source_file=winner.source_file,
                        line_number=winner.line_number,
                        excerpt=f"Likely winner by load order/listen precedence for '{name}'",
                        command="nginx -T (effective routing simulation)",
                    )
                )
            for diff in impact.get("diffs", [])[:4]:
                evidence_list.append(
                    Evidence(
                        source_file=diff.get("file", "nginx -T"),
                        line_number=1,
                        excerpt=(
                            "Shadow diff: "
                            f"location_delta={diff.get('locations_delta', 0)}, "
                            f"upstream_delta={diff.get('upstreams_delta', 0)}"
                        ),
                        command="nginx -T (winner vs shadowed diff)",
                    )
                )
            
            findings.append(
                Finding(
                    severity=severity,
                    confidence=0.96 if severity == Severity.WARNING else 0.9,
                    condition=f"Duplicate server_name '{name}'",
                    cause=(
                        f"Found {len(servers)} declarations across different blocks. "
                        f"Likely effective winner: {winner_ref}; shadowed blocks: {shadowed_count}. "
                        f"Effective impact: {impact['summary']}. "
                        f"Blast radius: {impact.get('blast_radius', 'unknown')}."
                        + (
                            " This appears to be a production/local split "
                            "(e.g., default.conf + default.local.conf) and is treated as "
                            "safe duplication unless routing behavior diverges."
                            if env_split and severity == Severity.INFO
                            else ""
                        )
                    ),
                    evidence=evidence_list,
                    treatment=(
                        (
                            "Optional cleanup: consolidate production/local split blocks if you want "
                            "a single source of truth. Current behavior is low-risk based on effective routing."
                            if env_split and severity == Severity.INFO
                            else "Keep one authoritative server block per server_name/listen pair. "
                            f"Prefer the winner at {winner_ref} and merge/remove shadowed definitions."
                        )
                    ),
                    impact=impact["impact_lines"],
                    correlation=impact.get("diffs", []),
                )
            )

        return findings

    def _simulate_routing_winner(self, servers: list[ServerBlock]) -> ServerBlock | None:
        """Best-effort simulation of which duplicated block wins matching precedence."""
        if not servers:
            return None

        def precedence(server: ServerBlock) -> tuple[int, int, int]:
            has_default = 1 if any("default_server" in listen for listen in server.listen) else 0
            has_ssl = 0 if any("443" in listen or "ssl" in listen.lower() for listen in server.listen) else 1
            return (has_default, has_ssl, server.line_number or 10**9)

        return sorted(servers, key=precedence)[0]

    def _has_overlapping_listens(self, servers: list[ServerBlock]) -> bool:
        if len(servers) <= 1:
            return False
        for i, left in enumerate(servers):
            left_bindings = self._extract_listen_bindings(left)
            for right in servers[i + 1 :]:
                right_bindings = self._extract_listen_bindings(right)
                if self._bindings_overlap(left_bindings, right_bindings):
                    return True
        return False

    @staticmethod
    def _extract_listen_bindings(server: ServerBlock) -> set[tuple[int, str]]:
        """Extract best-effort (port, address) bindings from listen directives."""
        bindings: set[tuple[int, str]] = set()
        for listen in server.listen or []:
            text = (listen or "").strip()
            if not text:
                continue
            first = text.split()[0]
            if first.startswith("unix:"):
                continue

            address = "*"
            port: int | None = None

            bracket_match = re.match(r"^\[([^\]]+)\](?::(\d+))?$", first)
            if bracket_match:
                raw_addr = bracket_match.group(1)
                raw_port = bracket_match.group(2)
                address = raw_addr
                if raw_port:
                    port = int(raw_port)
            elif ":" in first and first.count(":") == 1:
                raw_addr, raw_port = first.rsplit(":", 1)
                address = raw_addr.strip() or "*"
                if raw_port.isdigit():
                    port = int(raw_port)
            elif first.isdigit():
                port = int(first)
            else:
                # Example: listen default_server; (defaults to 80)
                for token in text.split():
                    if token.isdigit():
                        port = int(token)
                        break

            if port is None:
                port = 80

            addr_norm = address.strip().lower().strip("[]")
            if addr_norm in {"", "*", "0.0.0.0", "::"}:
                addr_norm = "*"
            bindings.add((port, addr_norm))

        if not bindings:
            bindings.add((80, "*"))
        return bindings

    @staticmethod
    def _bindings_overlap(
        left: set[tuple[int, str]],
        right: set[tuple[int, str]],
    ) -> bool:
        for l_port, l_addr in left:
            for r_port, r_addr in right:
                if l_port != r_port:
                    continue
                if l_addr == "*" or r_addr == "*" or l_addr == r_addr:
                    return True
        return False

    def _duplicate_server_effective_impact(self, winner: ServerBlock | None, shadowed: list[ServerBlock]) -> dict:
        if not winner or not shadowed:
            return {
                "severity": Severity.INFO,
                "summary": "insufficient routing context to estimate impact",
                "impact_lines": ["Configuration hygiene issue; effective impact unknown."],
                "blast_radius": "unknown",
                "diffs": [],
            }
        winner_sig = self._server_behavior_signature(winner)
        differs = []
        same = 0
        for candidate in shadowed:
            cand_sig = self._server_behavior_signature(candidate)
            if cand_sig == winner_sig:
                same += 1
                continue
            differs.append(
                {
                    "file": f"{candidate.source_file}:{candidate.line_number}",
                    "locations_delta": len(cand_sig["locations"] ^ winner_sig["locations"]),
                    "upstreams_delta": len(cand_sig["upstreams"] ^ winner_sig["upstreams"]),
                }
            )

        if not differs:
            return {
                "severity": Severity.INFO,
                "summary": "shadowed blocks are behaviorally equivalent to winner",
                "impact_lines": [
                    "Low immediate routing impact (duplicate definitions appear equivalent).",
                    "Configuration drift risk if copies diverge later.",
                ],
                "blast_radius": f"{same} shadowed block(s) equivalent",
                "diffs": [],
            }

        meaningful_upstream_diff = any(item["upstreams_delta"] > 0 for item in differs)
        if meaningful_upstream_diff:
            return {
                "severity": Severity.WARNING,
                "summary": "winner/shadowed blocks route to different upstream targets",
                "impact_lines": [
                    "Unpredictable request routing with meaningful backend differences.",
                    "One configuration may silently shadow a different upstream path.",
                ],
                "blast_radius": f"{len(differs)} shadowed block(s) differ on upstream routing",
                "diffs": differs,
            }

        only_non_behavioral_diff = all(
            item.get("upstreams_delta", 0) == 0 and item.get("locations_delta", 0) == 0
            for item in differs
        )
        if only_non_behavioral_diff:
            return {
                "severity": Severity.INFO,
                "summary": "duplicate blocks are effectively identical (cleanup-level duplication)",
                "impact_lines": [
                    "Low immediate routing impact (effective handler behavior is equivalent).",
                    "Cleanup recommended to prevent future drift between duplicate blocks.",
                ],
                "blast_radius": f"{len(differs)} shadowed block(s) with no location/upstream behavior delta",
                "diffs": differs,
            }

        return {
            "severity": Severity.WARNING,
            "summary": "winner/shadowed blocks differ in location behavior",
            "impact_lines": [
                "Request handling differs between duplicate server blocks.",
                "Shadowing can break expected path behavior under config changes.",
            ],
            "blast_radius": f"{len(differs)} shadowed block(s) differ on path/location behavior",
            "diffs": differs,
        }

    @staticmethod
    def _server_behavior_signature(server: ServerBlock) -> dict:
        locations: set[str] = set()
        upstreams: set[str] = set()
        for loc in server.locations or []:
            signature = "|".join(
                [
                    (loc.path or "").strip(),
                    (loc.proxy_pass or "").strip(),
                    (loc.fastcgi_pass or "").strip(),
                    (loc.root or "").strip(),
                    (loc.alias or "").strip(),
                    (loc.try_files or "").strip(),
                    (loc.return_directive or "").strip(),
                    "stub_status:on" if loc.stub_status else "",
                ]
            )
            locations.add(signature)
            if loc.proxy_pass:
                upstreams.add((loc.proxy_pass or "").strip())
            if loc.fastcgi_pass:
                upstreams.add((loc.fastcgi_pass or "").strip())
        listens = set((server.listen or []))
        return {"locations": locations, "upstreams": upstreams, "listen": listens}

    @staticmethod
    def _is_prod_local_split_duplicate(servers: list[ServerBlock]) -> bool:
        """Detect common default.conf + default.local.conf split patterns."""
        files = [((s.source_file or "").lower()) for s in servers]
        has_local = any(".local.conf" in f for f in files)
        has_non_local = any(f.endswith(".conf") and ".local.conf" not in f for f in files)
        return has_local and has_non_local

    def _check_path_routing_conflicts(self) -> list[Finding]:
        """Detect path-based routing conflicts across multi-project server blocks."""
        findings: list[Finding] = []
        if not self.model.nginx:
            return findings

        for server in self.model.nginx.servers:
            path_map: dict[str, list[LocationBlock]] = {}
            for location in server.locations:
                normalized = location.path.strip()
                if not normalized:
                    continue
                path_map.setdefault(normalized, []).append(location)

            for path, entries in path_map.items():
                if len(entries) <= 1:
                    continue

                proxy_targets = {(loc.proxy_pass or "").strip() for loc in entries if loc.proxy_pass}
                fastcgi_targets = {(loc.fastcgi_pass or "").strip() for loc in entries if loc.fastcgi_pass}

                if len(proxy_targets) <= 1 and len(fastcgi_targets) <= 1:
                    continue

                findings.append(
                    Finding(
                        id="NGX-ROUTE-1",
                        severity=Severity.WARNING,
                        confidence=0.9,
                        condition=f"Conflicting location path '{path}' in server block",
                        cause=(
                            f"Path '{path}' is declared {len(entries)} times with divergent backends, "
                            "which may produce precedence-dependent routing behavior."
                        ),
                        evidence=[
                            Evidence(
                                source_file=loc.source_file,
                                line_number=loc.line_number,
                                excerpt=(
                                    f"location {loc.path} -> proxy_pass={loc.proxy_pass or '-'} "
                                    f"fastcgi_pass={loc.fastcgi_pass or '-'}"
                                ),
                                command="nginx -T",
                            )
                            for loc in entries
                        ],
                        treatment="Consolidate duplicate location paths and keep one deterministic routing definition per path.",
                        impact=[
                            "Requests may be handled by unintended upstream",
                            "Shadow-routing bugs in multi-project setups",
                        ],
                    )
                )

        return findings

    def _check_backup_configs(self) -> list[Finding]:
        """Check for backup files in active configuration directories.
        
        Nginx often includes everything in /etc/nginx/sites-enabled/*,
        including .bak, .old, or .swp files.
        """
        findings: list[Finding] = []
        if not self.model.nginx:
            return findings

        backup_patterns = [".bak", ".old", ".save", ".orig", ".dpkg-dist", ".swp", "~"]
        backup_files: list[str] = []

        # Check all included files
        for file_path in self.model.nginx.includes:
            if "/sites-enabled/" in file_path and any(p in file_path for p in backup_patterns):
                backup_files.append(file_path)

        if backup_files:
            evidence = []
            # Premium: Add the include directive that caused this (Root Cause Evidence)
            if "include /etc/nginx/sites-enabled/*" in self.raw_config:
                evidence.append(
                    Evidence(
                        source_file="nginx.conf",
                        line_number=1,
                        excerpt="include /etc/nginx/sites-enabled/*;",
                        command="nginx -T",
                    )
                )
            
            evidence.extend([
                Evidence(
                    source_file=f,
                    line_number=1,
                    excerpt="File matched backup pattern and is in sites-enabled",
                    command="ls /etc/nginx/sites-enabled",
                )
                for f in backup_files
            ])

            # Generate actionable commands
            move_cmds = [f"sudo mv {f} /etc/nginx/backups/" for f in backup_files]
            treatment = (
                "Move backups out of include paths to a dedicated folder:\n"
                "sudo mkdir -p /etc/nginx/backups\n" +
                "\n".join(move_cmds) +
                "\nsudo nginx -t && sudo systemctl reload nginx"
            )

            findings.append(
                Finding(
                    severity=Severity.WARNING,
                    confidence=1.0,
                    condition="Backup configuration files are enabled",
                    cause=f"Found {len(backup_files)} backup/temp files being loaded by Nginx in sites-enabled",
                    evidence=evidence,
                    treatment=treatment,
                    impact=[
                        "Duplicate server_name conflicts (Real cause of many warnings)",
                        "Unexpected configuration behavior",
                        "Security risk if old configs are exposed",
                    ],
                )
            )

        return findings

    def _check_sites_enabled_structure(self) -> list[Finding]:
        """Verify that sites-enabled only contains symlinks, not flat files."""
        findings: list[Finding] = []
        return findings

    def _check_default_sites_enabled(self) -> list[Finding]:
        """Check if default nginx sites are still enabled."""
        findings: list[Finding] = []

        if not self.model.nginx:
            return findings

        for server in self.model.nginx.servers:
            if server.is_default_server and "default" in server.source_file:
                findings.append(
                    Finding(
                        severity=Severity.INFO,
                        confidence=0.80,
                        condition="Default nginx site still enabled",
                        cause="The default nginx site configuration is active",
                        evidence=[
                            Evidence(
                                source_file=server.source_file,
                                line_number=server.line_number,
                                excerpt="server { ... }",
                                command="nginx -T",
                            )
                        ],
                        treatment=(
                            f"Consider disabling:\nsudo rm {server.source_file}\n"
                            "sudo nginx -t && sudo systemctl reload nginx"
                        ),
                        impact=[
                            "May catch requests meant for other sites",
                            "Exposes default nginx page",
                        ],
                    )
                )

        return findings
