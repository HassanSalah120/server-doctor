import os
import json
from dataclasses import asdict
from datetime import datetime
from enum import Enum
from pathlib import Path
from jinja2 import Environment, FileSystemLoader, select_autoescape
import re
from typing import Any

from server_doctor.engine.scoring import ScoringEngine
from server_doctor.model.evidence import Severity
from server_doctor.model.server import ServerModel
from server_doctor.model.finding import Finding
from server_doctor.actions.html_report_enhancements import HTMLReportEnhancements
from server_doctor.utils.redaction import redact_value

class HTMLReportAction:
    """Action to generate a user-friendly HTML diagnostic report."""

    def __init__(self, template_dir: str | None = None) -> None:
        if template_dir is None:
            template_dir = os.path.join(os.path.dirname(__file__), "..", "templates")
        
        self.env = Environment(
            loader=FileSystemLoader(template_dir),
            autoescape=select_autoescape(["html", "xml"]),
        )
        self.template = self.env.get_template("report.html")

    def generate(
        self, 
        model: ServerModel, 
        findings: list[Finding] | None = None, 
        output_path: str = "report.html",
        unreferenced: list | None = None,
        static_noise: list | None = None,
        ws_inventory: list | None = None,
        trend: dict | None = None,
        suppressed_findings: list | None = None,
        waiver_source: str | None = None,
    ) -> str:
        """Generate the HTML report and save it to a file.
        
        Returns:
            The absolute path of the generated report.
        """
        findings_data = findings or []
        ws_data = ws_inventory or []
        suppressed_data = suppressed_findings or []

        display_findings = self._group_findings(findings_data)
        action_plan = self._build_action_plan(display_findings, limit=5)
        report_score = ScoringEngine().calculate(display_findings).total

        # Build enhancements
        executive_summary = HTMLReportEnhancements.build_executive_summary(
            display_findings, report_score, model
        )
        compliance_status = HTMLReportEnhancements.build_compliance_status(
            display_findings, model
        )
        remediation_tracker = HTMLReportEnhancements.build_remediation_tracker(
            display_findings
        )
        integration_config = HTMLReportEnhancements.build_integration_config(model)
        filter_categories = HTMLReportEnhancements.build_filter_categories(
            display_findings
        )

        model_json = json.dumps(redact_value(asdict(model)), indent=2, default=self._json_default)
        findings_json = json.dumps(
            redact_value([asdict(f) for f in findings_data]),
            indent=2,
            default=self._json_default,
        )

        findings_chart_data = [
            {"id": finding.id, "severity": finding.severity.value.upper()}
            for finding in display_findings
        ]

        disk_rows = self._filter_disk_rows(model)
        network_endpoints = self._dedupe_network_endpoints(model)
        ws_data = self._dedupe_ws_inventory(ws_data)
        traffic_flow = self._build_traffic_flow(model, ws_data)
        routing_winners = self._build_effective_routing_winners(model, ws_data)
        header_graph = self._build_header_inheritance_graph(model)
        exposure_map = self._build_exposure_map(model)
        tls_status = self._build_tls_status(model)
        upstream_probe_rows = self._build_upstream_probe_rows(model)
        ws_probe_lookup = self._build_ws_probe_lookup(model, ws_data)
        architecture_summary = self._build_architecture_summary(
            model=model,
            findings=display_findings,
            traffic_flow=traffic_flow,
            exposure_map=exposure_map,
            ws_inventory=ws_data,
        )
        role_profile = self._infer_role_profile(model)
        risk_buckets = self._classify_risk_buckets(display_findings, role_profile)
        fix_tracks = self._build_fix_tracks(display_findings)
        patch_snippets = self._build_patch_snippets(display_findings)
        resource_metrics = self._build_resource_metrics(model)

        html_content = self.template.render(
            model=model,
            findings=findings_data,
            display_findings=display_findings,
            model_json=model_json,
            findings_json=findings_json,
            findings_chart_data=findings_chart_data,
            disk_rows=disk_rows,
            network_endpoints=network_endpoints,
            traffic_flow=traffic_flow,
            routing_winners=routing_winners,
            header_graph=header_graph,
            exposure_map=exposure_map,
            tls_status=tls_status,
            upstream_probe_rows=upstream_probe_rows,
            ws_probe_lookup=ws_probe_lookup,
            architecture_summary=architecture_summary,
            role_profile=role_profile,
            risk_buckets=risk_buckets,
            fix_tracks=fix_tracks,
            patch_snippets=patch_snippets,
            action_plan=action_plan,
            report_score=report_score,
            resource_metrics=resource_metrics,
            # New enhancements
            executive_summary=executive_summary,
            compliance_status=compliance_status,
            remediation_tracker=remediation_tracker,
            integration_config=integration_config,
            filter_categories=filter_categories,
            trend=trend
            or {
                "has_previous": False,
                "new_findings": [],
                "resolved_findings": [],
                "score_delta": None,
                "previous_score": None,
                "current_score": None,
                "previous_timestamp": None,
                "current_timestamp": None,
                "topology_diff": None,
            },
            suppressed_findings=suppressed_data,
            waiver_source=waiver_source,
            unreferenced=unreferenced or [],
            static_noise=static_noise or [],
            ws_inventory=ws_data,
            now=datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        )

        out_path = Path(output_path).expanduser()
        out_path.parent.mkdir(parents=True, exist_ok=True)
        with out_path.open("w", encoding="utf-8") as f:
            f.write(html_content)

        return str(out_path.resolve())

    @staticmethod
    def _json_default(obj: object) -> str:
        if isinstance(obj, Enum):
            return obj.value
        return str(obj)

    @staticmethod
    def _filter_disk_rows(model: ServerModel) -> list:
        if not model.telemetry or not model.telemetry.disks:
            return []

        rows = []
        seen_mounts: set[str] = set()
        for disk in model.telemetry.disks:
            mount = disk.mount or ""
            if mount in seen_mounts:
                continue
            # Hide noisy per-container overlay mounts from top-level report table.
            if mount.startswith("/var/lib/docker/overlay2/") and mount.endswith("/merged"):
                continue
            seen_mounts.add(mount)
            rows.append(disk)
        return rows[:12]

    @staticmethod
    def _dedupe_network_endpoints(model: ServerModel) -> list:
        if not model.network_surface or not model.network_surface.endpoints:
            return []

        unique = []
        seen: set[tuple[str, str, int, str, bool]] = set()
        for ep in model.network_surface.endpoints:
            key = (
                ep.protocol,
                ep.address,
                ep.port,
                (ep.service or "unknown"),
                ep.public_exposed,
            )
            if key in seen:
                continue
            seen.add(key)
            unique.append(ep)
        return unique

    @staticmethod
    def _dedupe_ws_inventory(ws_inventory: list) -> list:
        if not ws_inventory:
            return []

        unique = []
        seen: set[tuple[str, str, str, str]] = set()
        for ws in ws_inventory:
            ws_path = getattr(getattr(ws, "location", None), "path", "")
            key = (ws.domain, ws_path, ws.proxy_target, ws.risk_level)
            if key in seen:
                continue
            seen.add(key)
            unique.append(ws)
        return unique

    @staticmethod
    def _group_findings(findings: list[Finding]) -> list[Finding]:
        """Collapse repetitive finding clusters for primary report views."""
        grouped: dict[str, list[Finding]] = {}
        passthrough: list[Finding] = []

        for finding in findings:
            condition = finding.condition.lower()
            fid = finding.id.upper()
            if (
                fid.startswith("NGX000")
                and (
                    "docker port" in condition
                    or any((ev.command or "").lower().startswith("docker") for ev in finding.evidence)
                )
            ):
                grouped.setdefault("DOCKER_EXPOSURE", []).append(finding)
                continue

            if fid.startswith("SEC-HEAD-1") or "missing security headers in location" in condition:
                grouped.setdefault("SEC_HEADERS", []).append(finding)
                continue

            if (
                "missing dotfile protection" in condition
                and (fid.startswith("NGX-SEC-3") or fid.startswith("NGX-WSS-010") or fid in {"NGX-2", "NGX-3"})
            ):
                grouped.setdefault("DOTFILE", []).append(finding)
                continue
            if fid.startswith("ROUTE-1") and finding.severity == Severity.INFO and "expected precedence" in condition.lower():
                grouped.setdefault("ROUTE_EXPECTED", []).append(finding)
                continue

            passthrough.append(finding)

        merged: list[Finding] = list(passthrough)
        for group_key, items in grouped.items():
            if group_key == "DOCKER_EXPOSURE":
                non_ingress = [i for i in items if not HTMLReportAction._is_ingress_exposure_finding(i)]
                ingress_like = [i for i in items if HTMLReportAction._is_ingress_exposure_finding(i)]
                merged.extend(ingress_like)
                if len(non_ingress) == 1:
                    merged.append(non_ingress[0])
                elif len(non_ingress) > 1:
                    merged.append(HTMLReportAction._merge_group("NGX000", non_ingress))
                continue
            if len(items) == 1:
                merged.append(items[0])
                continue
            if group_key == "SEC_HEADERS":
                merged.append(HTMLReportAction._merge_security_headers_group(items))
            elif group_key == "DOTFILE":
                merged.append(HTMLReportAction._merge_dotfile_group(items))
            elif group_key == "ROUTE_EXPECTED":
                merged.append(HTMLReportAction._merge_route_expected_group(items))

        return sorted(
            merged,
            key=lambda f: (
                0 if f.severity == Severity.CRITICAL else 1 if f.severity == Severity.WARNING else 2,
                f.id,
            ),
        )

    @staticmethod
    def _merge_route_expected_group(items: list[Finding]) -> Finding:
        evidence = [ev for f in items for ev in f.evidence][:12]
        routes = []
        for finding in items:
            routes.append({"id": finding.id, "condition": finding.condition})
        return Finding(
            id="ROUTE-GROUP",
            severity=Severity.INFO,
            confidence=max(i.confidence for i in items),
            condition=f"Expected precedence overlaps detected ({len(items)} route pair(s))",
            cause="Nginx is applying normal longest-prefix/exact-match precedence for these overlaps; no direct misrouting evidence detected.",
            evidence=evidence,
            treatment="No urgent fix required. Keep for hygiene/advanced review.",
            impact=["Low immediate risk; informational routing hygiene."],
            correlation=routes[:20],
        )

    @staticmethod
    def _merge_group(prefix: str, items: list[Finding]) -> Finding:
        severity_order = {Severity.CRITICAL: 0, Severity.WARNING: 1, Severity.INFO: 2}
        highest = sorted(items, key=lambda f: severity_order[f.severity])[0].severity
        confidence = max(i.confidence for i in items)

        evidence_seen: set[tuple[str, int, str]] = set()
        evidence = []
        has_non_ingress_port = any(
            (port := HTMLReportAction._extract_primary_host_port(finding)) is not None and port not in {80, 443}
            for finding in items
        )
        for finding in items:
            for ev in finding.evidence:
                if has_non_ingress_port and HTMLReportAction._evidence_mentions_ingress(ev.excerpt):
                    continue
                key = (ev.source_file, ev.line_number, ev.excerpt)
                if key in evidence_seen:
                    continue
                evidence_seen.add(key)
                evidence.append(ev)
        evidence = evidence[:12]

        impact: list[str] = []
        seen_impact: set[str] = set()
        for finding in items:
            for line in finding.impact:
                if line in seen_impact:
                    continue
                seen_impact.add(line)
                impact.append(line)

        ports = HTMLReportAction._extract_ports_from_findings(items)
        ports_text = ", ".join(str(p) for p in ports) if ports else "multiple ports"
        treatment = (
            "Consolidate public exposure through Nginx only.\n"
            "1. Rebind direct container ports to localhost.\n"
            f"2. Review and close exposed ports: {ports_text}.\n"
            "3. Keep only explicitly required public listeners."
        )

        # Collect all fix commands from individual findings
        all_fix_commands = []
        for f in items:
            if f.fix_commands:
                all_fix_commands.extend(f.fix_commands)

        return Finding(
            id=f"{prefix}-GROUP",
            severity=highest,
            confidence=confidence,
            condition=f"Multiple Docker ports are exposed publicly bypassing Nginx ({len(items)} findings)",
            cause="Several container ports are directly published on public interfaces instead of being constrained behind the intended reverse-proxy path.",
            evidence=evidence,
            treatment=treatment,
            fix_commands=all_fix_commands[:10] if all_fix_commands else [],
            impact=impact
            or [
                "Bypasses Nginx authentication/rate-limits",
                "Expands direct attack surface",
            ],
        )

    @staticmethod
    def _extract_primary_host_port(finding: Finding) -> int | None:
        condition_match = re.search(r"docker port\s+(\d{2,5})", finding.condition.lower())
        if condition_match:
            return int(condition_match.group(1))
        for ev in finding.evidence:
            match = re.search(r":(\d{2,5})\s*->", ev.excerpt)
            if match:
                return int(match.group(1))
        return None

    @staticmethod
    def _is_ingress_exposure_finding(finding: Finding) -> bool:
        port = HTMLReportAction._extract_primary_host_port(finding)
        if port not in {80, 443}:
            return False
        condition = finding.condition.lower()
        return "bypassing nginx" in condition or "public and also routed through nginx" in condition

    @staticmethod
    def _evidence_mentions_ingress(excerpt: str) -> bool:
        return bool(re.search(r":(?:80|443)\s*->", excerpt))

    @staticmethod
    def _merge_security_headers_group(items: list[Finding]) -> Finding:
        locations = HTMLReportAction._extract_location_labels(items)
        files = sorted({ev.source_file for f in items for ev in f.evidence if ev.source_file})
        evidence = [ev for f in items for ev in f.evidence][:12]
        # Collect all fix commands from individual findings
        all_fix_commands = []
        for f in items:
            if f.fix_commands:
                all_fix_commands.extend(f.fix_commands)
        return Finding(
            id="SEC-HEADERS-GROUP",
            severity=Severity.WARNING,
            confidence=max(i.confidence for i in items),
            condition=f"Missing security headers across {len(locations)} location(s)",
            cause=(
                "Child location blocks define add_header directives, which can clear inherited headers. "
                "This creates inconsistent security coverage across API/health/static endpoints."
            ),
            evidence=evidence,
            treatment=(
                "Centralize headers in a shared include and re-apply them in any location that sets add_header.\n"
                "Suggested fix path:\n"
                "1. Create include file with complete header set.\n"
                "2. Include it in server block and in overriding child locations.\n"
                "3. Validate with: nginx -t && systemctl reload nginx."
            ),
            fix_commands=all_fix_commands[:10] if all_fix_commands else [],
            impact=[
                "Inconsistent browser-side security policy",
                "Clickjacking/MIME-sniffing/referrer leakage risk on selected routes",
            ],
            correlation=[
                {"locations": locations[:12], "files": files[:6]},
            ],
        )

    @staticmethod
    def _merge_dotfile_group(items: list[Finding]) -> Finding:
        servers = sorted({HTMLReportAction._extract_server_label(i.condition) for i in items})
        evidence = [ev for f in items for ev in f.evidence][:12]
        # Collect all fix commands from individual findings
        all_fix_commands = []
        for f in items:
            if f.fix_commands:
                all_fix_commands.extend(f.fix_commands)
        return Finding(
            id="SEC-DOTFILE-GROUP",
            severity=Severity.WARNING,
            confidence=max(i.confidence for i in items),
            condition=f"Dotfile protection is missing or inconsistent across {len(servers)} server context(s)",
            cause="Not all active server blocks define a deny rule for dotfiles.",
            evidence=evidence,
            treatment=(
                "Apply one reusable snippet globally and preserve ACME challenge path:\n"
                "location ~ /\\.(?!well-known).* { deny all; }\n"
                "Then run: nginx -t && systemctl reload nginx."
            ),
            fix_commands=all_fix_commands[:10] if all_fix_commands else [],
            impact=[
                "Sensitive files like .env/.git can become web-accessible on misrouted paths",
            ],
            correlation=[{"servers": [s for s in servers if s][:10]}],
        )

    @staticmethod
    def _extract_ports_from_findings(findings: list[Finding]) -> list[int]:
        ports: set[int] = set()
        for finding in findings:
            for ev in finding.evidence:
                for match in re.findall(r"(?::|\s)(\d{2,5})(?=\s|$|/)", ev.excerpt):
                    value = int(match)
                    if 1 <= value <= 65535 and value not in {22, 80, 443}:
                        ports.add(value)
        return sorted(ports)

    @staticmethod
    def _build_action_plan(findings: list[Finding], limit: int = 5) -> list[dict]:
        """Create top-N prioritized remediation actions with commands."""
        ordered = sorted(
            findings,
            key=lambda f: (
                0 if f.severity == Severity.CRITICAL else 1 if f.severity == Severity.WARNING else 2,
                -f.confidence,
            ),
        )

        plan = []
        for index, finding in enumerate(ordered[:limit], start=1):
            plan.append(
                {
                    "rank": index,
                    "id": finding.id,
                    "severity": finding.severity.value.upper(),
                    "title": finding.condition,
                    "impact": finding.impact[0] if finding.impact else "Operational/security risk remains.",
                    "command": HTMLReportAction._recommended_command(finding),
                }
            )
        return plan

    @staticmethod
    def _recommended_command(finding: Finding) -> str:
        prefix = finding.id.split("-")[0].upper()
        fid = finding.id.upper()

        if fid.startswith("SYSTEMD"):
            service = "certbot.service"
            match = re.search(r"Service '([^']+)' has failed", finding.condition)
            if match:
                service = match.group(1)
            return (
                f"sudo systemctl restart {service}\n"
                f"sudo journalctl -u {service} -n 100 --no-pager"
            )

        if fid.startswith("CERTBOT"):
            return (
                "sudo systemctl status certbot.service certbot.timer --no-pager\n"
                "sudo journalctl -u certbot.service -n 120 --no-pager\n"
                "sudo certbot renew --dry-run -v\n"
                "sudo systemctl enable --now certbot.timer"
            )

        if prefix == "NGX000":
            ports = HTMLReportAction._extract_ports_from_findings([finding])
            if ports:
                port_lines = "\n".join(f"sudo ufw deny {p}/tcp" for p in ports)
                return f"sudo docker ps --format 'table {{.Names}}\\t{{.Ports}}'\n{port_lines}"
            return "sudo docker ps --format 'table {{.Names}}\\t{{.Ports}}'"

        if fid == "SSH-1":
            return (
                "sudo sed -i 's/^#\\?PasswordAuthentication .*/PasswordAuthentication no/' /etc/ssh/sshd_config\n"
                "sudo sshd -t && sudo systemctl reload ssh"
            )

        if prefix == "SEC":
            return "sudo nginx -t && sudo systemctl reload nginx"

        if prefix == "NGX002":
            return "sudo nginx -T | grep -n 'server_name' | sort"

        if prefix == "VULN":
            return "sudo apt-get update && sudo apt-get -y upgrade"

        if prefix == "NGX":
            return "sudo nginx -t && sudo systemctl reload nginx"

        return "Review treatment steps and validate with: sudo nginx -t"

    @staticmethod
    def _extract_location_labels(items: list[Finding]) -> list[str]:
        labels: list[str] = []
        pattern = re.compile(r"location\s+'([^']+)'|location\s+\"([^\"]+)\"|location\s+([^\s]+)")
        for finding in items:
            m = pattern.search(finding.condition)
            if not m:
                continue
            label = next((g for g in m.groups() if g), "").strip()
            if label and label not in labels:
                labels.append(label)
        return labels

    @staticmethod
    def _extract_server_label(condition: str) -> str:
        match = re.search(r"Server\s+\[([^\]]+)\]", condition)
        if match:
            return match.group(1)
        return ""

    @staticmethod
    def _build_architecture_summary(
        model: ServerModel,
        findings: list[Finding],
        traffic_flow: list[dict[str, Any]],
        exposure_map: list[dict[str, Any]],
        ws_inventory: list,
    ) -> list[str]:
        domains = sorted({route["domain"] for route in traffic_flow if route.get("domain")})
        duplicate_server_findings = [f for f in findings if f.id.startswith("NGX002")]
        public_exposed = [entry for entry in exposure_map if entry.get("public")]
        summary = [
            f"Nginx mode: {model.nginx.mode if model.nginx else 'unknown'}",
            f"Domains in routing graph: {len(domains)}",
            f"Route edges mapped: {len(traffic_flow)}",
            f"WebSocket routes: {len(ws_inventory)}",
            f"Public Docker binds: {len(public_exposed)}",
            f"Duplicate server_name conflicts: {len(duplicate_server_findings)}",
        ]
        project_types = sorted(
            {
                (p.type.value if hasattr(p.type, 'value') else str(p.type))
                for p in (model.projects or [])
                if p.type
            }
        )
        if project_types:
            summary.append(f"Detected project roles: {', '.join(project_types[:5])}")
        return summary

    @staticmethod
    def _build_traffic_flow(model: ServerModel, ws_inventory: list) -> list[dict[str, Any]]:
        if not model.nginx:
            return []

        upstream_map = {u.name: list(u.servers) for u in model.nginx.upstreams}
        ws_keys = {
            (
                getattr(ws, "domain", ""),
                getattr(getattr(ws, "location", None), "path", ""),
            )
            for ws in ws_inventory
        }
        flow_rows: list[dict[str, Any]] = []
        seen: set[tuple[str, str, str]] = set()
        for server in model.nginx.servers:
            domain = server.server_names[0] if server.server_names else "_"
            listen_ports = [HTMLReportAction._extract_listen_port(v) for v in server.listen if HTMLReportAction._extract_listen_port(v)]
            for location in server.locations:
                target = (location.proxy_pass or "").strip()
                route_type = "proxy"
                if not target:
                    if location.fastcgi_pass:
                        target = location.fastcgi_pass
                        route_type = "php-fpm"
                    elif location.root or server.root:
                        target = location.root or server.root or ""
                        route_type = "static"
                    else:
                        continue

                resolved_targets = [target]
                if route_type == "proxy":
                    upstream_name = HTMLReportAction._extract_upstream_name(target)
                    if upstream_name and upstream_name in upstream_map and upstream_map[upstream_name]:
                        resolved_targets = upstream_map[upstream_name]

                for resolved in resolved_targets:
                    key = (domain, location.path, resolved)
                    if key in seen:
                        continue
                    seen.add(key)
                    backend_port = HTMLReportAction._extract_port_from_target(resolved)
                    container_links = HTMLReportAction._match_containers(model, backend_port)
                    host_ports = sorted(
                        {
                            cport["host_port"]
                            for c in container_links
                            for cport in c["ports"]
                            if cport.get("host_port") is not None
                        }
                    )
                    public = any(
                        HTMLReportAction._is_public_bind(cport.get("host_ip", ""))
                        for c in container_links
                        for cport in c["ports"]
                    )
                    is_ws = (domain, location.path) in ws_keys
                    confidence = 0
                    confidence_reasons: list[str] = []
                    if location.source_file:
                        confidence += 1
                        confidence_reasons.append("location source known")
                    if route_type != "proxy":
                        confidence += 1
                        confidence_reasons.append("local route target")
                    if backend_port is not None:
                        confidence += 1
                        confidence_reasons.append("backend port resolved")
                    if container_links:
                        confidence += 1
                        confidence_reasons.append("container mapped")
                    unknown = route_type == "proxy" and (backend_port is None or not container_links)
                    confidence_label = HTMLReportAction._flow_confidence_label(confidence, unknown)
                    flow_rows.append(
                        {
                            "domain": domain,
                            "listen_ports": listen_ports,
                            "path": location.path,
                            "route_type": "websocket" if is_ws else route_type,
                            "target": target,
                            "resolved_target": resolved,
                            "backend_port": backend_port,
                            "containers": [c["name"] for c in container_links],
                            "host_ports": host_ports,
                            "public": public,
                            "confidence": confidence,
                            "confidence_label": confidence_label,
                            "unknown": unknown,
                            "confidence_reasons": confidence_reasons,
                            "source_file": location.source_file,
                            "line_number": location.line_number,
                        }
                    )
        return sorted(flow_rows, key=lambda row: (row["domain"], row["path"], row["resolved_target"]))

    @staticmethod
    def _flow_confidence_label(score: int, unknown: bool) -> str:
        if unknown:
            return "UNKNOWN"
        if score >= 4:
            return "HIGH"
        if score >= 2:
            return "MEDIUM"
        return "LOW"

    @staticmethod
    def _build_effective_routing_winners(model: ServerModel, ws_inventory: list | None = None) -> list[dict[str, Any]]:
        if not model.nginx:
            return []
        probes = HTMLReportAction._collect_probe_paths(model, ws_inventory or [])
        domains = sorted(
            {
                name
                for server in model.nginx.servers
                for name in (server.server_names or ["_"])
                if name and name != "_"
            }
        )
        if not domains:
            domains = ["_"]

        rows: list[dict[str, Any]] = []
        for host in domains:
            server = HTMLReportAction._select_server_winner_for_host(model, host)
            for probe in probes:
                location = HTMLReportAction._select_location_winner(server, probe) if server else None
                target = "-"
                if location:
                    target = location.proxy_pass or location.fastcgi_pass or location.root or server.root or "-"
                rows.append(
                    {
                        "host": host,
                        "probe": probe,
                        "winner_file": server.source_file if server else "unknown",
                        "winner_line": server.line_number if server else 0,
                        "location_path": location.path if location else "(server default)",
                        "target": target,
                        "confidence": "HIGH" if server else "UNKNOWN",
                    }
                )
        return rows

    @staticmethod
    def _collect_probe_paths(model: ServerModel, ws_inventory: list) -> list[str]:
        """Canonical probes + discovered high-value paths from live config."""
        canonical = ["/", "/api", "/health", "/wss", "/socket.io/"]
        discovered: set[str] = set()

        if model.nginx:
            for server in model.nginx.servers:
                for location in server.locations:
                    raw = (location.path or "").strip()
                    if not raw:
                        continue
                    normalized = HTMLReportAction._normalize_location_probe(raw)
                    if normalized:
                        discovered.add(normalized)

                    lowered = raw.lower()
                    if "api|auth" in lowered or ("api" in lowered and "auth" in lowered):
                        discovered.update({"/api", "/auth"})
                    if "socket.io" in lowered:
                        discovered.add("/socket.io/")
                    if "/ws" in lowered or "wss" in lowered:
                        discovered.add("/wss")
                    if any(token in lowered for token in ["/assets", "/build", "/static", "/dist"]):
                        for token in ["/assets/", "/build/", "/static/", "/dist/"]:
                            if token.rstrip("/") in lowered:
                                discovered.add(token)

        for ws in ws_inventory:
            ws_path = (getattr(getattr(ws, "location", None), "path", "") or "").strip()
            normalized = HTMLReportAction._normalize_location_probe(ws_path)
            if normalized:
                discovered.add(normalized)

        dynamic_sorted = sorted(
            [p for p in discovered if p not in canonical],
            key=lambda p: (len(p), p),
        )
        return canonical + dynamic_sorted

    @staticmethod
    def _normalize_location_probe(location_path: str) -> str | None:
        path = location_path.strip()
        if not path:
            return None
        if path.startswith("="):
            path = path[1:].strip()
        if path.startswith("^~"):
            path = path[2:].strip()
        if path.startswith("~"):
            # Regex routes are mapped to canonical known probes elsewhere.
            return None
        if not path.startswith("/"):
            return None
        # Keep likely probe-ready static/app prefixes deterministic.
        if path in {"/", "/api", "/auth", "/health", "/wss"}:
            return path
        if path.startswith("/socket.io"):
            return "/socket.io/"
        if path.startswith("/assets"):
            return "/assets/"
        if path.startswith("/build"):
            return "/build/"
        if path.startswith("/static"):
            return "/static/"
        if path.startswith("/dist"):
            return "/dist/"
        # Keep direct explicit paths (e.g., /wss19, /api/v1)
        if len(path) <= 64:
            return path
        return None

    @staticmethod
    def _select_server_winner_for_host(model: ServerModel, host: str):
        if not model.nginx:
            return None

        def server_rank(server) -> tuple[int, int, int]:
            names = server.server_names or ["_"]
            if host in names:
                host_rank = 0
            elif any(n.startswith("*.") and host.endswith(n[1:]) for n in names):
                host_rank = 1
            elif server.is_default_server or "_" in names:
                host_rank = 2
            else:
                host_rank = 3
            ssl_rank = 0 if any("443" in listen or "ssl" in listen.lower() for listen in server.listen) else 1
            return (host_rank, ssl_rank, server.line_number or 10**9)

        candidates = sorted(model.nginx.servers, key=server_rank)
        if not candidates:
            return None
        best = candidates[0]
        if server_rank(best)[0] == 3:
            return None
        return best

    @staticmethod
    def _select_location_winner(server, probe_path: str):
        if not server:
            return None
        exact_matches = []
        prefix_matches = []
        regex_matches = []
        for location in server.locations:
            lp = (location.path or "").strip()
            if not lp:
                continue
            if lp.startswith("="):
                expected = lp[1:].strip()
                if probe_path == expected:
                    exact_matches.append(location)
                continue
            if lp.startswith("^~"):
                prefix = lp[2:].strip()
                if probe_path.startswith(prefix):
                    prefix_matches.append((len(prefix), location))
                continue
            if lp.startswith("~"):
                pattern = lp[1:].strip()
                try:
                    if re.search(pattern, probe_path):
                        regex_matches.append(location)
                except re.error:
                    continue
                continue
            if probe_path.startswith(lp):
                prefix_matches.append((len(lp), location))

        if exact_matches:
            return sorted(exact_matches, key=lambda loc: loc.line_number or 10**9)[0]
        if prefix_matches:
            return sorted(prefix_matches, key=lambda item: (-item[0], item[1].line_number or 10**9))[0][1]
        if regex_matches:
            return sorted(regex_matches, key=lambda loc: loc.line_number or 10**9)[0]
        return None

    @staticmethod
    def _build_header_inheritance_graph(model: ServerModel) -> list[dict[str, Any]]:
        if not model.nginx:
            return []
        rows: list[dict[str, Any]] = []
        global_headers = model.nginx.http_headers or {}
        seen: set[tuple[str, str, str, int]] = set()
        for server in model.nginx.servers:
            domain = server.server_names[0] if server.server_names else "_"
            server_headers = server.headers or global_headers
            for location in server.locations:
                if not location.path:
                    continue
                key = (
                    domain,
                    location.path,
                    location.source_file or "",
                    int(location.line_number or 0),
                )
                if key in seen:
                    continue
                seen.add(key)
                child_headers = location.headers or {}
                if child_headers:
                    mode = "override"
                    missing = sorted([h for h in server_headers.keys() if h not in child_headers])
                elif server_headers:
                    mode = "inherit"
                    missing = []
                else:
                    mode = "unknown"
                    missing = []
                rows.append(
                    {
                        "domain": domain,
                        "path": location.path,
                        "mode": mode,
                        "parent_count": len(server_headers),
                        "child_count": len(child_headers),
                        "missing": missing[:6],
                        "source_file": location.source_file,
                        "line_number": location.line_number,
                    }
                )
        return rows

    @staticmethod
    def _build_exposure_map(model: ServerModel) -> list[dict[str, Any]]:
        if not model.services:
            return []
        proxied_ports = HTMLReportAction._extract_nginx_backend_ports(model)
        firewall_missing = (model.services.firewall or "").lower() == "not_detected"
        ingress_containers = HTMLReportAction._detect_ingress_containers(model)
        ingress_count = len(ingress_containers)
        rows: list[dict[str, Any]] = []
        dev_ports = {3000, 3001, 4173, 5173, 8080, 8081}
        for container in model.services.docker_containers:
            for mapping in container.ports:
                if mapping.host_port is None:
                    continue
                public = HTMLReportAction._is_public_bind(mapping.host_ip)
                if not public:
                    continue
                proxied = mapping.container_port in proxied_ports
                is_ingress_container = container.name in ingress_containers
                if mapping.host_port in dev_ports:
                    bucket = "real_risk"
                    severity = "CRITICAL"
                    reason = "Dev-oriented service port is exposed publicly."
                elif mapping.host_port in {80, 443} and is_ingress_container:
                    if mapping.host_port == 443 and ingress_count > 1:
                        bucket = "cleanup"
                        severity = "WARNING"
                        reason = "Multiple ingress containers publish 443; keep one authoritative ingress."
                    else:
                        bucket = "info"
                        severity = "INFO"
                        reason = "Expected ingress exposure on reverse-proxy container."
                elif mapping.host_port == 443 and container.name not in ingress_containers:
                    bucket = "real_risk"
                    severity = "WARNING"
                    reason = "HTTPS 443 exposed by a non-ingress container."
                elif not proxied and firewall_missing:
                    bucket = "real_risk"
                    severity = "CRITICAL"
                    reason = "Public port is not proxied by Nginx and no firewall was detected."
                elif not proxied:
                    bucket = "real_risk"
                    severity = "WARNING"
                    reason = "Public container port bypasses reverse-proxy policy path."
                else:
                    bucket = "cleanup"
                    severity = "WARNING"
                    reason = "Public port is also proxied; consider localhost binding to reduce bypass risk."
                fw_posture, fw_evidence = HTMLReportAction._classify_firewall_posture(
                    model, mapping.host_port, mapping.proto
                )
                if fw_posture == "BLOCKED":
                    if severity == "CRITICAL":
                        severity = "WARNING"
                    elif severity == "WARNING":
                        severity = "INFO"
                    reason = f"{reason} Blocked today but published (latent risk if firewall policy changes)."

                rows.append(
                    {
                        "container": container.name,
                        "image": container.image,
                        "host_ip": mapping.host_ip,
                        "host_port": mapping.host_port,
                        "container_port": mapping.container_port,
                        "proto": mapping.proto,
                        "public": public,
                        "proxied": proxied,
                        "proxied_display": "N/A (ingress)" if (is_ingress_container and mapping.host_port in {80, 443}) else ("yes" if proxied else "no"),
                        "bucket": bucket,
                        "severity": severity,
                        "reason": reason,
                        "firewall_posture": fw_posture,
                        "firewall_evidence": fw_evidence,
                    }
                )
        return sorted(
            rows,
            key=lambda r: (
                0 if r["severity"] == "CRITICAL" else 1 if r["severity"] == "WARNING" else 2,
                r["host_port"],
            ),
        )

    @staticmethod
    def _classify_risk_buckets(findings: list[Finding], role_profile: dict[str, bool] | None = None) -> dict[str, list[dict[str, str]]]:
        buckets = {"real_risk": [], "cleanup": [], "info": []}
        role_profile = role_profile or {}
        high_risk_prefixes = {
            "NGX000",
            "SSH-1",
            "CERTBOT-1",
            "NET-1",
            "NET-2",
            "MYSQL-1",
            "NGX-WSS-001",
            "NGX-WSS-002",
            "NGX-WSS-003",
        }
        for finding in findings:
            fid = finding.id.upper()
            if role_profile.get("websocket_service") and fid.startswith("ROUTE-2"):
                key = "real_risk"
            elif role_profile.get("react_frontend") and fid.startswith("NGX000") and "5173" in finding.condition:
                key = "real_risk"
            elif role_profile.get("reverse_proxy") and fid in {"DOCKER-3"}:
                key = "info"
            elif role_profile.get("node_api") and fid.startswith("DRIFT-1"):
                key = "real_risk"
            elif role_profile.get("node_api") and fid.startswith("DRIFT-2"):
                key = "cleanup"
            elif finding.severity == Severity.CRITICAL or any(fid.startswith(x) for x in high_risk_prefixes):
                key = "real_risk"
            elif finding.severity == Severity.WARNING:
                key = "cleanup"
            else:
                key = "info"
            buckets[key].append(
                {
                    "id": finding.id,
                    "severity": finding.severity.value.upper(),
                    "condition": finding.condition,
                }
            )
        return buckets

    @staticmethod
    def _build_fix_tracks(findings: list[Finding]) -> dict[str, list[dict[str, str]]]:
        ranked = sorted(
            findings,
            key=lambda f: (
                0 if f.severity == Severity.CRITICAL else 1 if f.severity == Severity.WARNING else 2,
                -f.confidence,
            ),
        )

        def entry(finding: Finding) -> dict[str, str]:
            return {
                "id": finding.id,
                "condition": finding.condition,
                "command": HTMLReportAction._recommended_command(finding),
            }

        five_minute: list[dict[str, str]] = []
        security: list[dict[str, str]] = []
        cleanup: list[dict[str, str]] = []

        for finding in ranked:
            fid = finding.id.upper()
            if len(five_minute) < 5 and finding.severity != Severity.INFO:
                five_minute.append(entry(finding))
            if len(security) < 5 and (
                fid.startswith("SEC")
                or fid.startswith("SSH")
                or fid.startswith("NGX000")
                or fid.startswith("NGX-WSS")
            ):
                security.append(entry(finding))
            if len(cleanup) < 5 and finding.severity == Severity.INFO:
                cleanup.append(entry(finding))

        return {"five_minute": five_minute, "security": security, "cleanup": cleanup}

    @staticmethod
    def _extract_nginx_backend_ports(model: ServerModel) -> set[int]:
        ports: set[int] = set()
        if not model.nginx:
            return ports
        upstream_ports: dict[str, set[int]] = {}
        for upstream in model.nginx.upstreams:
            parsed_ports = {
                p
                for p in (HTMLReportAction._extract_port_from_target(s) for s in upstream.servers)
                if p is not None
            }
            upstream_ports[upstream.name] = parsed_ports

        for server in model.nginx.servers:
            for location in server.locations:
                proxy = (location.proxy_pass or "").strip()
                if not proxy:
                    continue
                direct = HTMLReportAction._extract_port_from_target(proxy)
                if direct is not None:
                    ports.add(direct)
                    continue
                upstream_name = HTMLReportAction._extract_upstream_name(proxy)
                if upstream_name and upstream_name in upstream_ports:
                    ports.update(upstream_ports[upstream_name])
        return ports

    @staticmethod
    def _match_containers(model: ServerModel, backend_port: int | None) -> list[dict[str, Any]]:
        if backend_port is None:
            return []
        matched: list[dict[str, Any]] = []
        for container in model.services.docker_containers:
            matching_ports = [
                {
                    "host_ip": p.host_ip,
                    "host_port": p.host_port,
                    "container_port": p.container_port,
                    "proto": p.proto,
                }
                for p in container.ports
                if p.container_port == backend_port
            ]
            if matching_ports:
                matched.append({"name": container.name, "ports": matching_ports})
        return matched

    @staticmethod
    def _is_public_bind(host_ip: str) -> bool:
        return host_ip in {"0.0.0.0", "::", ""}

    @staticmethod
    def _extract_listen_port(listen: str) -> int | None:
        value = listen.split()[0] if listen else ""
        if "]:" in value:
            value = value.rsplit("]:", 1)[1]
        elif ":" in value and not value.startswith("["):
            value = value.rsplit(":", 1)[1]
        return int(value) if value.isdigit() else None

    @staticmethod
    def _extract_port_from_target(target: str) -> int | None:
        cleaned = target.strip().rstrip(";")
        for prefix in ("http://", "https://"):
            if cleaned.startswith(prefix):
                cleaned = cleaned[len(prefix):]
        if cleaned.startswith("unix:"):
            return None
        if "/" in cleaned:
            cleaned = cleaned.split("/", 1)[0]
        if cleaned.startswith("[") and "]:" in cleaned:
            cleaned = cleaned.rsplit("]:", 1)[1]
        elif ":" in cleaned:
            cleaned = cleaned.rsplit(":", 1)[1]
        return int(cleaned) if cleaned.isdigit() else None

    @staticmethod
    def _extract_upstream_name(proxy_pass: str) -> str | None:
        cleaned = proxy_pass.strip().rstrip(";")
        for prefix in ("http://", "https://"):
            if cleaned.startswith(prefix):
                cleaned = cleaned[len(prefix):]
        if "/" in cleaned:
            cleaned = cleaned.split("/", 1)[0]
        if ":" in cleaned or cleaned.startswith("["):
            return None
        return cleaned if cleaned else None

    @staticmethod
    def _detect_ingress_containers(model: ServerModel) -> set[str]:
        ingress_keywords = ("nginx", "reverse-proxy", "proxy", "traefik", "caddy", "haproxy")
        names: set[str] = set()
        for container in (model.services.docker_containers or []):
            cname = (container.name or "").lower()
            image = (container.image or "").lower()
            publishes_ingress = any(
                p.host_port in {80, 443} and HTMLReportAction._is_public_bind(p.host_ip)
                for p in (container.ports or [])
                if p.host_port is not None
            )
            if publishes_ingress and any(k in cname or k in image for k in ingress_keywords):
                names.add(container.name)
        return names

    @staticmethod
    def _infer_role_profile(model: ServerModel) -> dict[str, bool]:
        project_types = {
            (p.type.value if hasattr(p.type, "value") else str(p.type)).lower()
            for p in (model.projects or [])
            if p.type
        }
        has_ws_route = any(
            "/ws" in (loc.path or "").lower() or "socket.io" in (loc.path or "").lower()
            for s in (model.nginx.servers or []) if model.nginx
            for loc in (s.locations or [])
        ) if model.nginx else False
        reverse_proxy = bool(model.nginx and model.nginx.servers)
        api_route_present = any(
            any(token in (loc.path or "").lower() for token in ("/api", "/auth"))
            for s in (model.nginx.servers or []) if model.nginx
            for loc in (s.locations or [])
        ) if model.nginx else False
        static_route_present = any(
            any(token in (loc.path or "").lower() for token in ("/assets", "/build", "/static", "/dist"))
            for s in (model.nginx.servers or []) if model.nginx
            for loc in (s.locations or [])
        ) if model.nginx else False
        dev_ports = {3000, 3001, 4173, 5173, 8080, 8081}
        dev_server_exposed = any(
            (p.host_port in dev_ports) and HTMLReportAction._is_public_bind(p.host_ip)
            for c in (getattr(model.services, "docker_containers", []) or [])
            for p in (getattr(c, "ports", []) or [])
            if p.host_port is not None
        )
        frontend_app = bool(
            {"react_frontend", "react_source", "react_spa", "react_static_build", "static"} & project_types
        ) or static_route_present
        api_service = bool({"node_api", "nextjs", "nuxt"} & project_types) or api_route_present
        return {
            "reverse_proxy": reverse_proxy or "reverse_proxy" in project_types,
            "frontend_app": frontend_app,
            "api_service": api_service,
            "websocket_service": has_ws_route or ("websocket_service" in project_types),
            "dev_server_exposed": dev_server_exposed,
            # Backward-compatible aliases used by earlier UI bucketing logic.
            "react_frontend": frontend_app,
            "node_api": api_service,
        }

    @staticmethod
    def _build_tls_status(model: ServerModel) -> list[dict[str, Any]]:
        rows: list[dict[str, Any]] = []
        tls = getattr(model, "tls", None)
        certs = getattr(tls, "certificates", []) if tls else []
        for cert in certs or []:
            renewal_owner = HTMLReportAction._detect_tls_renewal_owner(model, cert)
            owner_unknown_alert = (
                cert.days_remaining is not None
                and cert.days_remaining < 14
                and renewal_owner == "unknown"
            )
            # Visual countdown status
            days = cert.days_remaining
            if days is None:
                expiry_status = "unknown"
                expiry_color = "gray"
                expiry_urgent = False
            elif days <= 7:
                expiry_status = "critical"
                expiry_color = "red"
                expiry_urgent = True
            elif days <= 30:
                expiry_status = "warning"
                expiry_color = "orange"
                expiry_urgent = True
            elif days <= 60:
                expiry_status = "caution"
                expiry_color = "yellow"
                expiry_urgent = False
            else:
                expiry_status = "healthy"
                expiry_color = "green"
                expiry_urgent = False
            
            rows.append(
                {
                    "path": cert.path,
                    "issuer": cert.issuer or "unknown",
                    "subject": cert.subject or "unknown",
                    "expires_at": cert.expires_at or "unknown",
                    "days_remaining": cert.days_remaining,
                    "sans": cert.sans[:8] if cert.sans else [],
                    "parse_ok": cert.parse_ok,
                    "renewal_owner": renewal_owner,
                    "owner_unknown_alert": owner_unknown_alert,
                    # Visual countdown fields
                    "expiry_status": expiry_status,
                    "expiry_color": expiry_color,
                    "expiry_urgent": expiry_urgent,
                }
            )
        # fallback from certbot when tls parsing is unavailable
        if not rows and getattr(model, "certbot", None):
            for path in (model.certbot.active_cert_paths or []):
                renewal_owner = "certbot" if (model.certbot.installed and model.certbot.timer_enabled) else "unknown"
                days = model.certbot.min_days_to_expiry
                owner_unknown_alert = (
                    days is not None
                    and days < 14
                    and renewal_owner == "unknown"
                )
                # Visual countdown for fallback
                if days is None:
                    expiry_status = "unknown"
                    expiry_color = "gray"
                    expiry_urgent = False
                elif days <= 7:
                    expiry_status = "critical"
                    expiry_color = "red"
                    expiry_urgent = True
                elif days <= 30:
                    expiry_status = "warning"
                    expiry_color = "orange"
                    expiry_urgent = True
                elif days <= 60:
                    expiry_status = "caution"
                    expiry_color = "yellow"
                    expiry_urgent = False
                else:
                    expiry_status = "healthy"
                    expiry_color = "green"
                    expiry_urgent = False
                
                rows.append(
                    {
                        "path": path,
                        "issuer": "unknown",
                        "subject": "unknown",
                        "expires_at": "unknown",
                        "days_remaining": days,
                        "sans": [],
                        "parse_ok": False,
                        "renewal_owner": renewal_owner,
                        "owner_unknown_alert": owner_unknown_alert,
                        # Visual countdown fields
                        "expiry_status": expiry_status,
                        "expiry_color": expiry_color,
                        "expiry_urgent": expiry_urgent,
                    }
                )
        return rows

    @staticmethod
    def _detect_tls_renewal_owner(model: ServerModel, cert: Any) -> str:
        issuer = (getattr(cert, "issuer", "") or "").lower()
        certbot = getattr(model, "certbot", None)
        if certbot and certbot.installed and certbot.uses_letsencrypt_certs:
            return "certbot"
        if certbot and certbot.installed and ("let's encrypt" in issuer or "letsencrypt" in issuer):
            if certbot.timer_enabled or certbot.timer_active:
                return "certbot"
        if model.nginx and (model.nginx.mode or "").upper() == "DOCKER":
            return "container-managed"
        return "unknown"

    @staticmethod
    def _build_upstream_probe_rows(model: ServerModel) -> list[dict[str, Any]]:
        rows: list[dict[str, Any]] = []
        for probe in getattr(model, "upstream_probes", []) or []:
            rows.append(
                {
                    "target": probe.target,
                    "protocol": probe.protocol,
                    "reachable": probe.reachable,
                    "latency_ms": probe.latency_ms,
                    "detail": probe.detail or "",
                    "scope": getattr(probe, "scope", "host"),
                    "status": getattr(probe, "status", "UNKNOWN"),
                    "tcp_ok": getattr(probe, "tcp_ok", None),
                    "http_code": getattr(probe, "http_code", None),
                    "ws_code": getattr(probe, "ws_code", None),
                    "ws_status": getattr(probe, "ws_status", None),
                    "ws_detail": getattr(probe, "ws_detail", None),
                    "ws_path": getattr(probe, "ws_path", None),
                }
            )
        return sorted(rows, key=lambda r: (not r["reachable"], r["target"]))

    @staticmethod
    def _build_ws_probe_lookup(model: ServerModel, ws_inventory: list) -> dict[str, dict[str, Any]]:
        probes_by_target = {
            (getattr(p, "target", "") or ""): p
            for p in (getattr(model, "upstream_probes", []) or [])
            if getattr(p, "target", None)
        }
        lookup: dict[str, dict[str, Any]] = {}
        for ws in ws_inventory or []:
            ws_path = (getattr(getattr(ws, "location", None), "path", "") or "").strip()
            key = f"{getattr(ws, 'domain', '')}|{ws_path}"
            target = HTMLReportAction._resolve_ws_probe_target(model, getattr(ws, "proxy_target", "") or "")
            probe = probes_by_target.get(target)
            if not probe:
                continue
            lookup[key] = {
                "status": getattr(probe, "ws_status", None) or (str(getattr(probe, "ws_code", "")) if getattr(probe, "ws_code", None) is not None else "n/a"),
                "detail": getattr(probe, "ws_detail", None) or (getattr(probe, "detail", "") or ""),
                "path": getattr(probe, "ws_path", None) or ws_path,
            }
        return lookup

    @staticmethod
    def _resolve_ws_probe_target(model: ServerModel, proxy_target: str) -> str:
        cleaned = (proxy_target or "").strip().rstrip(";")
        if not cleaned:
            return ""
        for prefix in ("http://", "https://"):
            if cleaned.startswith(prefix):
                cleaned = cleaned[len(prefix):]
        if "/" in cleaned:
            cleaned = cleaned.split("/", 1)[0]
        if ":" in cleaned:
            return cleaned
        # Upstream name
        if model.nginx:
            for upstream in model.nginx.upstreams or []:
                if upstream.name == cleaned and upstream.servers:
                    first = (upstream.servers[0] or "").strip()
                    for prefix in ("http://", "https://"):
                        if first.startswith(prefix):
                            first = first[len(prefix):]
                    if "/" in first:
                        first = first.split("/", 1)[0]
                    return first
        return ""

    @staticmethod
    def _build_patch_snippets(findings: list[Finding]) -> dict[str, str]:
        has_docker_exposure = any(f.id.upper().startswith("NGX000") or f.id.upper().startswith("DOCKER-5") for f in findings)
        has_header_or_dot = any(f.id.upper().startswith("SEC") for f in findings)
        docker_patch = ""
        nginx_patch = ""
        if has_docker_exposure:
            docker_patch = (
                "services:\n"
                "  backend:\n"
                "    ports:\n"
                "      - \"127.0.0.1:3000:3000\"\n"
                "      - \"127.0.0.1:8104:8104\"\n"
                "  frontend:\n"
                "    ports:\n"
                "      - \"127.0.0.1:5173:80\"\n"
            )
        if has_header_or_dot:
            nginx_patch = (
                "# /etc/nginx/snippets/security_headers.inc\n"
                "add_header X-Frame-Options \"DENY\" always;\n"
                "add_header X-Content-Type-Options \"nosniff\" always;\n"
                "add_header Referrer-Policy \"strict-origin-when-cross-origin\" always;\n"
                "\n"
                "# include in server and overriding locations\n"
                "include /etc/nginx/snippets/security_headers.inc;\n"
                "location ~ /\\.(?!well-known).* { deny all; }\n"
            )
        return {"docker_compose": docker_patch, "nginx_include": nginx_patch}

    @staticmethod
    def _build_resource_metrics(model: ServerModel) -> dict[str, Any]:
        """Build visual resource metrics with usage percentages."""
        telemetry = getattr(model, "telemetry", None)
        if not telemetry:
            return {"has_data": False}
        
        metrics = {"has_data": True, "cpu": {}, "memory": {}, "disks": []}
        
        # CPU metrics
        cpu_cores = getattr(telemetry, "cpu_cores", None)
        load_1 = getattr(telemetry, "load_1", None)
        if cpu_cores and load_1 is not None:
            load_pct = min(100, round((load_1 / cpu_cores) * 100))
            metrics["cpu"] = {
                "cores": cpu_cores,
                "load_1": round(load_1, 2),
                "load_5": round(getattr(telemetry, "load_5", 0), 2),
                "load_15": round(getattr(telemetry, "load_15", 0), 2),
                "usage_percent": load_pct,
                "status": "critical" if load_pct > 90 else "warning" if load_pct > 70 else "healthy",
            }
        
        # Memory metrics
        mem_total = getattr(telemetry, "mem_total_mb", None)
        mem_available = getattr(telemetry, "mem_available_mb", None)
        if mem_total and mem_available is not None:
            used_mb = mem_total - mem_available
            used_pct = round((used_mb / mem_total) * 100)
            metrics["memory"] = {
                "total_gb": round(mem_total / 1024, 2),
                "available_gb": round(mem_available / 1024, 2),
                "used_gb": round(used_mb / 1024, 2),
                "used_percent": used_pct,
                "status": "critical" if used_pct > 90 else "warning" if used_pct > 80 else "healthy",
            }
        
        # Disk metrics (already collected)
        disks = getattr(telemetry, "disks", []) or []
        for disk in disks[:4]:  # Top 4 disks by usage
            metrics["disks"].append({
                "mount": disk.mount,
                "total_gb": disk.total_gb,
                "used_gb": disk.used_gb,
                "used_percent": disk.used_percent,
                "status": "critical" if disk.used_percent > 90 else "warning" if disk.used_percent > 80 else "healthy",
            })
        
        return metrics

    @staticmethod
    def _classify_firewall_posture(model: ServerModel, port: int, proto: str) -> tuple[str, str]:
        """Classify exposure posture using ufw correlation when available."""
        if not hasattr(model, "services"):
            return ("UNKNOWN", "services model unavailable")
        ufw_enabled = getattr(model.services, "firewall_ufw_enabled", None)
        default_incoming = (getattr(model.services, "firewall_ufw_default_incoming", None) or "").lower()
        rules = [str(r).lower() for r in (getattr(model.services, "firewall_rules", []) or [])]
        proto = (proto or "tcp").lower()
        if ufw_enabled is None:
            return ("UNKNOWN", "UFW state unavailable")
        if ufw_enabled is False:
            return ("OPEN", "UFW inactive")
        # ufw enabled: inspect matching rules for this port/proto
        allow = False
        deny = False
        token = f"{port}/{proto}"
        bare = f"{port}"
        matched_rules: list[str] = []
        for rule in rules:
            if token in rule or re.search(rf"\b{bare}\b", rule):
                matched_rules.append(rule)
                if "allow" in rule:
                    allow = True
                if "deny" in rule or "reject" in rule:
                    deny = True
        if allow and not deny:
            return ("OPEN", f"explicit allow rule ({matched_rules[0] if matched_rules else token})")
        if deny and not allow:
            return ("BLOCKED", f"explicit deny/reject rule ({matched_rules[0] if matched_rules else token})")
        if default_incoming in {"deny", "reject"}:
            return ("BLOCKED", "UFW default incoming policy blocks unmatched ports")
        if default_incoming == "allow":
            return ("OPEN", "UFW default incoming policy allows unmatched ports")
        return ("UNKNOWN", "No explicit matching rule and default incoming policy unknown")
