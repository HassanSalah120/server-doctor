"""Runtime Drift Auditor - Detect config/runtime mismatches."""

from __future__ import annotations

import re

from server_doctor.model.evidence import Evidence, Severity
from server_doctor.model.finding import Finding
from server_doctor.model.server import NetworkEndpoint, ServerModel


class RuntimeDriftAuditor:
    """Audits drift between Nginx routing config and live runtime state."""

    LOOPBACK_HOSTS = {"127.0.0.1", "localhost", "::1", "[::1]", "0.0.0.0", "::"}

    def __init__(self, model: ServerModel) -> None:
        self.model = model

    def audit(self) -> list[Finding]:
        findings: list[Finding] = []
        if not self.model.nginx:
            return findings

        findings.extend(self._check_unbacked_local_targets())
        findings.extend(self._check_unused_upstreams())
        return findings

    def _check_unbacked_local_targets(self) -> list[Finding]:
        expected_targets = self._collect_routing_targets()
        if not expected_targets:
            return []

        listening_ports = {
            ep.port
            for ep in self._iter_endpoints()
            if str(ep.protocol).lower() == "tcp"
        }
        node_ports = {
            port
            for proc in (self.model.services.node_processes or [])
            for port in (proc.listening_ports or [])
            if isinstance(port, int)
        }
        host_published_ports = {
            int(port.host_port)
            for c in (self.model.services.docker_containers or [])
            for port in (c.ports or [])
            if getattr(port, "host_port", None) is not None
        }
        container_ports_by_name = {
            (c.name or "").strip().lower(): {
                int(p.container_port)
                for p in (c.ports or [])
                if getattr(p, "container_port", None) is not None
            }
            for c in (self.model.services.docker_containers or [])
            if (c.name or "").strip()
        }
        php_sockets = set((self.model.php.sockets or []) if self.model.php else [])

        missing: list[tuple[str, str | None, int | None, str | None, str, int, str, str]] = []
        for target_kind, host, port, socket_path, source_file, line_number, target, via in expected_targets:
            if target_kind == "unix":
                has_runtime = bool(socket_path and socket_path in php_sockets)
                if not has_runtime:
                    missing.append((target_kind, None, None, socket_path, source_file, line_number, target, via))
                continue

            if not host or port is None:
                continue
            host_norm = host.strip().lower()
            has_runtime = False

            if host_norm in self.LOOPBACK_HOSTS:
                has_runtime = port in listening_ports or port in node_ports or port in host_published_ports
            elif host_norm in container_ports_by_name:
                has_runtime = port in container_ports_by_name[host_norm]
            else:
                # Unknown/external host cannot be confidently validated here.
                continue

            if not has_runtime:
                missing.append((target_kind, host, port, None, source_file, line_number, target, via))

        if not missing:
            return []

        evidence = [
            Evidence(
                source_file=source_file,
                line_number=line_number,
                excerpt=(
                    f"Target {target} ({via}) has no matching runtime listener/socket"
                ),
                command="nginx -T + ss -tulpn + docker ps",
            )
            for _, _, _, _, source_file, line_number, target, via in missing[:10]
        ]

        unique_targets = sorted({via for *_, via in missing})
        return [
            Finding(
                id="DRIFT-1",
                severity=Severity.WARNING,
                confidence=0.85,
                condition=f"{len(unique_targets)} Nginx target(s) have no matching runtime listener",
                cause=(
                    "Configured proxy/fastcgi routes point to local/container backends that do not "
                    "appear active in current runtime state."
                ),
                evidence=evidence,
                treatment=(
                    "Start or redeploy missing backend services, or update Nginx targets to active listeners. "
                    "Validate with: nginx -t and runtime port checks."
                ),
                impact=[
                    "Requests can fail with 502/504 due to dead backend targets",
                    "Routing behavior drifts from intended deployment topology",
                ],
            )
        ]

    def _check_unused_upstreams(self) -> list[Finding]:
        upstreams = self.model.nginx.upstreams or []
        if not upstreams:
            return []

        referenced: set[str] = set()
        has_indirect_proxy_refs = False
        for server in (self.model.nginx.servers or []):
            for location in (server.locations or []):
                for target in (location.proxy_pass, location.fastcgi_pass):
                    if target and "$" in target:
                        has_indirect_proxy_refs = True
                    upstream_name = self._extract_upstream_name(target or "")
                    if upstream_name:
                        referenced.add(upstream_name)

        unused = [up.name for up in upstreams if up.name not in referenced]
        if not unused:
            return []

        evidence = [
            Evidence(
                source_file=up.source_file or self.model.nginx.config_path or "nginx",
                line_number=up.line_number or 1,
                excerpt=f"upstream {up.name} declared but not referenced by any proxy/fastcgi location",
                command="nginx -T",
            )
            for up in upstreams
            if up.name in unused
        ]

        return [
            Finding(
                id="DRIFT-2",
                severity=Severity.INFO if has_indirect_proxy_refs else Severity.WARNING,
                confidence=0.75 if has_indirect_proxy_refs else 0.9,
                condition=(
                    f"{len(unused)} upstream block(s) appear unused"
                    + (" (indirect variable-based routing detected)" if has_indirect_proxy_refs else "")
                ),
                cause=(
                    "Declared upstreams are not referenced by active location proxy targets."
                    + (
                        " Some proxy_pass/fastcgi_pass directives are variable-based, so this may be partial."
                        if has_indirect_proxy_refs
                        else ""
                    )
                ),
                evidence=evidence[:10],
                treatment="Remove stale upstream blocks or wire them into active routes to reduce config drift.",
                impact=[
                    "Stale configuration increases maintenance risk",
                    "Can hide deployment leftovers and routing confusion",
                ],
            )
        ]

    def _collect_routing_targets(self) -> list[tuple[str, str | None, int | None, str | None, str, int, str, str]]:
        """Return list of (kind, host, port, socket_path, source_file, line_number, original_target, resolved_descriptor)."""
        upstream_map = {
            up.name: list(up.servers or [])
            for up in (self.model.nginx.upstreams or [])
        }
        results: list[tuple[str, str | None, int | None, str | None, str, int, str, str]] = []

        for server in (self.model.nginx.servers or []):
            for location in (server.locations or []):
                source_file = location.source_file or server.source_file or self.model.nginx.config_path or "nginx"
                line_number = location.line_number or server.line_number or 1

                for raw_target in (location.proxy_pass, location.fastcgi_pass):
                    target = (raw_target or "").strip()
                    if not target:
                        continue

                    upstream_name = self._extract_upstream_name(target)
                    if upstream_name and upstream_name in upstream_map:
                        for member in upstream_map[upstream_name]:
                            parsed = self._parse_target(member)
                            if parsed:
                                kind, value = parsed
                                if kind == "unix":
                                    descriptor = f"unix:{value}"
                                    results.append((kind, None, None, str(value), source_file, line_number, target, descriptor))
                                else:
                                    host, port = value
                                    descriptor = f"{host}:{port}"
                                    results.append((kind, host, port, None, source_file, line_number, target, descriptor))
                        continue

                    parsed = self._parse_target(target)
                    if parsed:
                        kind, value = parsed
                        if kind == "unix":
                            descriptor = f"unix:{value}"
                            results.append((kind, None, None, str(value), source_file, line_number, target, descriptor))
                        else:
                            host, port = value
                            descriptor = f"{host}:{port}"
                            results.append((kind, host, port, None, source_file, line_number, target, descriptor))

        return results

    def _iter_endpoints(self) -> list[NetworkEndpoint]:
        endpoints = getattr(getattr(self.model, "network_surface", None), "endpoints", None)
        return endpoints if isinstance(endpoints, list) else []

    @staticmethod
    def _extract_upstream_name(target: str) -> str | None:
        cleaned = target.strip().rstrip(";")
        for prefix in ("http://", "https://", "fastcgi://", "grpc://", "grpcs://"):
            if cleaned.startswith(prefix):
                cleaned = cleaned[len(prefix):]
        if not cleaned or cleaned.startswith("unix:"):
            return None
        if "/" in cleaned:
            cleaned = cleaned.split("/", 1)[0]
        if ":" in cleaned or cleaned.startswith("["):
            return None
        return cleaned

    @staticmethod
    def _parse_target(target: str) -> tuple[str, str | tuple[str, int]] | None:
        cleaned = target.strip().rstrip(";")
        for prefix in ("http://", "https://", "fastcgi://", "grpc://", "grpcs://"):
            if cleaned.startswith(prefix):
                cleaned = cleaned[len(prefix):]
        if not cleaned:
            return None
        if cleaned.startswith("unix:"):
            socket_path = cleaned[len("unix:") :].strip()
            return ("unix", socket_path) if socket_path else None
        if "/" in cleaned:
            cleaned = cleaned.split("/", 1)[0]

        # IPv6: [::1]:3000
        ipv6_match = re.match(r"^\[([^\]]+)\]:(\d+)$", cleaned)
        if ipv6_match:
            return "tcp", (ipv6_match.group(1), int(ipv6_match.group(2)))

        if ":" not in cleaned:
            return None

        host, _, port_str = cleaned.rpartition(":")
        if not host or not port_str.isdigit():
            return None
        return "tcp", (host, int(port_str))
