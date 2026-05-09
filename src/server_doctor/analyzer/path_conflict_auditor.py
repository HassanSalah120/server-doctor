"""Path Conflict Auditor - Detect overlapping Nginx location routing."""

from __future__ import annotations

import re

from server_doctor.model.evidence import Evidence, Severity
from server_doctor.model.finding import Finding
from server_doctor.model.server import LocationBlock, ServerBlock, ServerModel


class PathConflictAuditor:
    """Detect route conflicts that can shadow multi-project paths."""

    def __init__(self, model: ServerModel) -> None:
        self.model = model

    def audit(self) -> list[Finding]:
        if not self.model.nginx:
            return []
        findings: list[Finding] = []
        findings.extend(self._check_prefix_conflicts())
        findings.extend(self._check_websocket_regex_conflicts())
        return findings

    def _check_prefix_conflicts(self) -> list[Finding]:
        findings: list[Finding] = []
        seen: set[tuple[str, int, int]] = set()

        for server in self.model.nginx.servers or []:
            locations = server.locations or []
            for i in range(len(locations)):
                for j in range(i + 1, len(locations)):
                    a, b = locations[i], locations[j]
                    if not self._literal_like(a.path) or not self._literal_like(b.path):
                        continue
                    pa = self._normalize_literal_path(a.path)
                    pb = self._normalize_literal_path(b.path)
                    if not pa or not pb:
                        continue
                    if not self._paths_overlap(pa, pb):
                        continue

                    probe = self._example_probe(pa, pb)
                    winner = self._winner_for_probe(server, probe)
                    if winner is None or winner.path not in {a.path, b.path}:
                        continue
                    shadowed = b if winner.path == a.path else a
                    if winner.path == shadowed.path:
                        continue
                    winner_target = self._resolve_location_target(server, winner)
                    shadowed_target = self._resolve_location_target(server, shadowed)
                    target_differs = winner_target != shadowed_target
                    winner_broken, broken_reason = self._is_broken_route(server, winner, probe)
                    ambiguous_overlap = self._is_ambiguous_overlap(winner.path, shadowed.path)
                    
                    # Skip benign expected precedence entirely - it's normal Nginx behavior
                    if not winner_broken and not (target_differs and ambiguous_overlap):
                        continue
                    
                    conflict_class = (
                        "broken routing"
                        if winner_broken
                        else "suspicious overlap"
                    )

                    key = (id(server), min(i, j), max(i, j))
                    if key in seen:
                        continue
                    seen.add(key)

                    findings.append(
                        Finding(
                            id="ROUTE-1",
                            severity=Severity.CRITICAL if winner_broken else Severity.WARNING,
                            confidence=0.94 if winner_broken else 0.85,
                            condition=f"Route conflict ({conflict_class}) between '{a.path}' and '{b.path}'",
                            cause=(
                                f"Request probe '{probe}' is likely handled by '{winner.path}', "
                                f"which can shadow '{shadowed.path}' depending on location precedence. "
                                + (
                                    f"Winning handler is broken ({broken_reason})."
                                    if winner_broken
                                    else
                                    f"Routes point to different targets ({winner_target} vs {shadowed_target}) with ambiguous overlap."
                                )
                            ),
                            evidence=[
                                Evidence(
                                    source_file=winner.source_file or server.source_file or self.model.nginx.config_path,
                                    line_number=winner.line_number or server.line_number or 1,
                                    excerpt=f"Winning location for probe {probe}: {winner.path}",
                                    command="nginx -T (routing simulation)",
                                ),
                                Evidence(
                                    source_file=shadowed.source_file or server.source_file or self.model.nginx.config_path,
                                    line_number=shadowed.line_number or server.line_number or 1,
                                    excerpt=f"Shadowed candidate: {shadowed.path}",
                                    command="nginx -T",
                                ),
                            ],
                            treatment=(
                                "Disambiguate paths (e.g., normalize trailing slashes, use exact matches where needed) "
                                "and validate with canonical probe requests."
                            ),
                            impact=[
                                "Requests may fail due to missing or failed route handler"
                                if winner_broken
                                else "Requests may be routed to the wrong backend",
                                "One app path can unintentionally steal traffic from another app",
                            ],
                        )
                    )

        return findings

    def _resolve_location_target(self, server: ServerBlock, location: LocationBlock) -> str:
        if location.return_directive:
            return f"return:{location.return_directive}"
        if location.stub_status:
            return "handler:stub_status"
        target = (location.proxy_pass or location.fastcgi_pass or location.root or server.root or "-").strip()
        if not target:
            return "-"
        upstream_name = self._extract_upstream_name(target)
        if not upstream_name or not self.model.nginx:
            return target
        for upstream in self.model.nginx.upstreams or []:
            if upstream.name == upstream_name:
                members = ",".join(sorted(upstream.servers or []))
                return f"upstream:{upstream_name}=>{members}" if members else f"upstream:{upstream_name}"
        return target

    def _check_websocket_regex_conflicts(self) -> list[Finding]:
        findings: list[Finding] = []
        for server in self.model.nginx.servers or []:
            locations = server.locations or []
            regex_locations = [loc for loc in locations if self._location_kind(loc.path) == "regex"]
            ws_locations = [
                loc
                for loc in locations
                if self._literal_like(loc.path)
                and any(token in self._normalize_literal_path(loc.path) for token in ("/wss", "/ws", "/socket.io"))
            ]
            if not regex_locations or not ws_locations:
                continue

            for ws_loc in ws_locations:
                probe = self._normalize_literal_path(ws_loc.path)
                if not probe:
                    continue
                winner = self._winner_for_probe(server, probe)
                if winner is None:
                    continue
                if winner.path == ws_loc.path:
                    continue
                if self._location_kind(winner.path) != "regex":
                    continue

                findings.append(
                    Finding(
                        id="ROUTE-2",
                        severity=Severity.WARNING,
                        confidence=0.85,
                        condition=f"Route conflict (suspicious overlap) for WebSocket path '{ws_loc.path}'",
                        cause=(
                            f"Probe '{probe}' resolves to regex '{winner.path}' instead of explicit WebSocket "
                            f"location '{ws_loc.path}'."
                        ),
                        evidence=[
                            Evidence(
                                source_file=winner.source_file or server.source_file or self.model.nginx.config_path,
                                line_number=winner.line_number or server.line_number or 1,
                                excerpt=f"Regex winner for probe {probe}: {winner.path}",
                                command="nginx -T (routing simulation)",
                            ),
                            Evidence(
                                source_file=ws_loc.source_file or server.source_file or self.model.nginx.config_path,
                                line_number=ws_loc.line_number or server.line_number or 1,
                                excerpt=f"Intended WebSocket location: {ws_loc.path}",
                                command="nginx -T",
                            ),
                        ],
                        treatment=(
                            "Use a more specific WebSocket location (or `^~` where appropriate) and tighten regex "
                            "patterns so upgrade traffic is deterministic."
                        ),
                        impact=[
                            "WebSocket upgrade requests can hit the wrong backend",
                            "Intermittent realtime failures and routing drift",
                        ],
                    )
                )
        return findings

    @staticmethod
    def _literal_like(path: str) -> bool:
        kind = PathConflictAuditor._location_kind(path)
        return kind in {"exact", "prefix", "caret"}

    @staticmethod
    def _location_kind(path: str) -> str:
        p = (path or "").strip()
        if p.startswith("="):
            return "exact"
        if p.startswith("^~"):
            return "caret"
        if p.startswith("~"):
            return "regex"
        return "prefix"

    @staticmethod
    def _normalize_literal_path(path: str) -> str:
        p = (path or "").strip()
        if p.startswith("="):
            p = p[1:].strip()
        elif p.startswith("^~"):
            p = p[2:].strip()
        return p

    @staticmethod
    def _paths_overlap(a: str, b: str) -> bool:
        if a == b:
            return True
        if a.endswith("/"):
            if b.startswith(a):
                return True
        else:
            if b == a + "/" or b.startswith(a + "/"):
                return True
        if b.endswith("/"):
            if a.startswith(b):
                return True
        else:
            if a == b + "/" or a.startswith(b + "/"):
                return True
        return False

    @staticmethod
    def _example_probe(a: str, b: str) -> str:
        base = a if len(a) >= len(b) else b
        if base.rstrip("/") == "/health":
            return "/health?probe=1"
        if base.endswith("/"):
            return base + "probe"
        return base + "/probe"

    def _winner_for_probe(self, server: ServerBlock, probe: str) -> LocationBlock | None:
        path_only = probe.split("?", 1)[0]
        locations = server.locations or []
        exact_match: LocationBlock | None = None
        caret_best: tuple[int, LocationBlock] | None = None
        prefix_best: tuple[int, LocationBlock] | None = None

        for loc in locations:
            kind = self._location_kind(loc.path)
            if kind == "exact":
                exact = self._normalize_literal_path(loc.path)
                if path_only == exact:
                    exact_match = loc
                    break
            elif kind == "caret":
                prefix = self._normalize_literal_path(loc.path)
                if prefix and self._path_matches_prefix(path_only, prefix):
                    size = len(prefix)
                    if caret_best is None or size > caret_best[0]:
                        caret_best = (size, loc)
            elif kind == "prefix":
                prefix = self._normalize_literal_path(loc.path)
                if prefix and self._path_matches_prefix(path_only, prefix):
                    size = len(prefix)
                    if prefix_best is None or size > prefix_best[0]:
                        prefix_best = (size, loc)

        if exact_match:
            return exact_match
        if caret_best:
            return caret_best[1]

        for loc in locations:
            if self._location_kind(loc.path) != "regex":
                continue
            pattern = self._extract_regex_pattern(loc.path)
            if not pattern:
                continue
            try:
                if re.search(pattern, path_only):
                    return loc
            except re.error:
                continue

        return prefix_best[1] if prefix_best else None

    def _is_broken_route(self, server: ServerBlock, location: LocationBlock, probe: str) -> tuple[bool, str]:
        if not self._has_valid_handler(server, location):
            return True, "no valid handler directive (proxy/fastcgi/root/alias/try_files/return/stub_status)"

        proxy_target = (location.proxy_pass or "").strip()
        if proxy_target:
            if self._is_missing_named_upstream(proxy_target):
                return True, "proxy_pass references missing upstream target"
            probe_state = self._probe_status_for_target(proxy_target)
            if probe_state == "BLOCKED":
                return True, f"active probe indicates upstream failure for probe '{probe}'"

        fastcgi_target = (location.fastcgi_pass or "").strip()
        php_sockets_known = bool(getattr(getattr(self.model, "php", None), "sockets", []))
        if (
            fastcgi_target
            and fastcgi_target.startswith("unix:")
            and php_sockets_known
            and not self._has_socket_declared(fastcgi_target)
        ):
            return True, "fastcgi unix socket not present in discovered PHP sockets"

        return False, "ok"

    @staticmethod
    def _has_valid_handler(server: ServerBlock, location: LocationBlock) -> bool:
        if location.return_directive:
            return True
        if location.stub_status:
            return True
        if location.proxy_pass or location.fastcgi_pass:
            return True
        if location.try_files:
            return True
        if location.alias or location.root or server.root:
            return True
        return False

    def _is_missing_named_upstream(self, target: str) -> bool:
        upstream_name = self._extract_upstream_name(target)
        if not upstream_name or not self.model.nginx:
            return False
        upstream_names = {u.name for u in (self.model.nginx.upstreams or [])}
        return upstream_name not in upstream_names

    def _probe_status_for_target(self, target: str) -> str | None:
        probe_results = getattr(self.model, "upstream_probes", []) or []
        host_port = self._extract_host_port(target)
        if not host_port:
            return None
        for probe in probe_results:
            if (getattr(probe, "target", "") or "") == host_port:
                return (getattr(probe, "status", "") or "").upper() or None
        return None

    @staticmethod
    def _extract_host_port(target: str) -> str | None:
        cleaned = target.strip().rstrip(";")
        for prefix in ("http://", "https://", "fastcgi://", "grpc://", "grpcs://"):
            if cleaned.startswith(prefix):
                cleaned = cleaned[len(prefix):]
                break
        if cleaned.startswith("unix:"):
            return None
        if "/" in cleaned:
            cleaned = cleaned.split("/", 1)[0]
        if ":" not in cleaned:
            return None
        host, _, port = cleaned.rpartition(":")
        if not host or not port.isdigit():
            return None
        return f"{host}:{port}"

    def _has_socket_declared(self, socket_target: str) -> bool:
        path = socket_target.replace("unix:", "").strip()
        php = getattr(self.model, "php", None)
        if not php:
            return False
        return path in set(getattr(php, "sockets", []) or [])

    @staticmethod
    def _path_matches_prefix(path: str, prefix: str) -> bool:
        if prefix == "/":
            return path.startswith("/")
        if path == prefix:
            return True
        if prefix.endswith("/"):
            return path.startswith(prefix)
        return path.startswith(prefix + "/")

    @staticmethod
    def _extract_regex_pattern(path: str) -> str | None:
        p = (path or "").strip()
        if p.startswith("~*"):
            return p[2:].strip()
        if p.startswith("~"):
            return p[1:].strip()
        return None

    @staticmethod
    def _extract_upstream_name(target: str) -> str | None:
        cleaned = target.strip().rstrip(";")
        for prefix in ("http://", "https://"):
            if cleaned.startswith(prefix):
                cleaned = cleaned[len(prefix):]
        if "/" in cleaned:
            cleaned = cleaned.split("/", 1)[0]
        if ":" in cleaned or cleaned.startswith("[") or "$" in cleaned:
            return None
        return cleaned if cleaned else None

    @staticmethod
    def _is_ambiguous_overlap(path_a: str, path_b: str) -> bool:
        a = PathConflictAuditor._normalize_literal_path(path_a).rstrip("/")
        b = PathConflictAuditor._normalize_literal_path(path_b).rstrip("/")
        if not a or not b:
            return False
        # /api and /api/ variants are easy to mis-handle and can be ambiguous by request shape.
        if a == b and path_a != path_b:
            return True
        return False
