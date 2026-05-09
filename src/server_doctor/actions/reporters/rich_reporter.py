"""Rich Reporter Implementation."""

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from server_doctor.actions.reporters.base import BaseReporter
from server_doctor.model.evidence import Severity
from server_doctor.model.finding import Finding
from server_doctor.model.server import ServerModel


class RichReporter(BaseReporter):
    """Generates high-fidelity terminal output using Rich."""

    def report_findings(self, findings: list[Finding]) -> int:
        """Report diagnosis findings to the console."""
        # Sort by severity
        sorted_findings = sorted(
            findings, 
            key=lambda x: (
                0 if x.severity == Severity.CRITICAL else 
                1 if x.severity == Severity.WARNING else 2
            )
        )

        warning_count = sum(1 for f in findings if f.severity == Severity.WARNING)
        critical_count = sum(1 for f in findings if f.severity == Severity.CRITICAL)
        info_count = len(findings) - warning_count - critical_count

        self.console.print()
        
        if self.show_score:
            self._print_score_summary(findings)
            self.console.print()

        self.console.print("Diagnosis Results", style="bold underline")
        self.console.print(f"   Summary: {critical_count} critical, {warning_count} warning, {info_count} info")
        self.console.print()

        for finding in sorted_findings:
            self._print_finding(finding)

        return 1 if warning_count > 0 or critical_count > 0 else 0

    def _print_score_summary(self, findings: list[Finding]) -> None:
        """Print the 0-100 score card."""
        from server_doctor.engine.scoring import ScoringEngine
        scorer = ScoringEngine()
        score = scorer.calculate(findings)
        
        total_color = "red"
        if score.total >= 80: total_color = "green"
        elif score.total >= 60: total_color = "yellow"
        
        grid = Table.grid(expand=True)
        grid.add_column()
        grid.add_column(justify="right")
        
        def row(name, cur, max_p):
            c = "green" if cur == max_p else ("yellow" if cur > max_p/2 else "red")
            grid.add_row(name, f"[{c}]{cur}[/][dim]/{max_p}[/]")
            
        row("Security", score.security.current_points, score.security.max_points)
        row("Performance", score.performance.current_points, score.performance.max_points)
        row("Architecture", score.architecture.current_points, score.architecture.max_points)
        row("Laravel/App", score.app.current_points, score.app.max_points)
        
        self.console.print(Panel(
            grid,
            title=f"[{total_color}]Server Health Score: {score.total}/100[/]",
            border_style=total_color
        ))

    def _print_finding(self, finding: Finding) -> None:
        """Print a single finding."""
        color = "white"
        icon = "i"
        if finding.severity == Severity.CRITICAL:
            color = "red"
            icon = "x"
        elif finding.severity == Severity.WARNING:
            color = "yellow"
            icon = "!"
        elif finding.severity == Severity.INFO:
            color = "blue"
            icon = "i"

        title = f"[{color}][{finding.severity.value}] {icon} [{finding.id}] {finding.condition}[/]"
        if finding.derived_from:
            title += f" [dim](derived_from={finding.derived_from})[/]"
        
        self.console.print(title)
        self.console.print(f"   [dim]Cause:[/] {finding.cause}")
        self.console.print(f"   [dim]Confidence:[/] {finding.confidence:.0%}")

        self.console.print("   [dim]Evidence:[/]")
        for evidence in finding.evidence:
            loc = f"{evidence.source_file}:{evidence.line_number}"
            self.console.print(f"      - {loc}")
            if evidence.excerpt:
                self.console.print(f"         [italic]{evidence.excerpt}[/]")

        if finding.treatment:
            treatment_text = str(finding.treatment)
            if "\n" in treatment_text:
                is_command = "sudo " in treatment_text
                p_title = "[bold white]Terminal Action[/]" if is_command else "[bold white]Configuration Change[/]"
                border = "green" if is_command else "blue"
                
                self.console.print(
                    Panel(
                        f"[green]{treatment_text}[/]" if is_command else f"[blue]{treatment_text}[/]",
                        title=p_title,
                        title_align="left",
                        border_style=border,
                        padding=(1, 2)
                    )
                )
            else:
                self.console.print(f"   [dim]Treatment:[/] [green]{finding.treatment}[/]")

        if finding.impact:
            self.console.print("   [dim]Impact if ignored:[/]")
            for impact in finding.impact:
                self.console.print(f"      ! {impact}")
        
        if self.show_explain:
            from server_doctor.engine.knowledge_base import get_explanation
            expl = get_explanation(finding.id)
            if expl:
                self.console.print("   [bold cyan]Explanation:[/]")
                self.console.print(f"      [cyan]Why:[/cyan] {expl.why}")
                self.console.print(f"      [cyan]Risk:[/cyan] {expl.risk}")
                self.console.print(f"      [cyan]Ignore if:[/cyan] {expl.ignore}")
        
        self.console.print()

    def report_server_summary(self, model: ServerModel, findings: list[Finding] | None = None) -> None:
        """Display server summary."""
        self.console.print()
        self.console.print(Panel.fit(f"📋 Server: {model.hostname}", style="bold cyan"))

        if model.os:
            self.console.print(f"   OS: {model.os.full_name}")
        if model.nginx:
            source_info = f"[bold]{model.nginx.mode}[/]"
            if model.nginx.container_id:
                source_info += f" [dim]({model.nginx.container_id[:12]})[/]"
            self.console.print(f"   Nginx: {model.nginx.version} ({source_info})")
            self.console.print(f"   Server Blocks: {len(model.nginx.servers)}")
        if model.php:
            self.console.print(f"   PHP: {', '.join(model.php.versions)}")
            self.console.print(f"   FPM Sockets: {len(model.php.sockets)}")
        if model.services:
            self.console.print(
                f"   Services: MySQL={model.services.mysql.state.value}, "
                f"Firewall={model.services.firewall}"
            )
        if model.vulnerability:
            v = model.vulnerability
            if v.provider != "unknown" or v.cve_ids or v.advisory_ids:
                self.console.print(
                    f"   Vulnerabilities: provider={v.provider}, "
                    f"cves={len(v.cve_ids)}, advisories={len(v.advisory_ids)}, packages={len(v.affected_packages)}"
                )
        if model.network_surface and model.network_surface.endpoints:
            public_eps = [ep for ep in model.network_surface.endpoints if ep.public_exposed]
            self.console.print(
                f"   Network Surface: endpoints={len(model.network_surface.endpoints)}, public={len(public_eps)}"
            )
        if model.security_baseline:
            b = model.security_baseline
            pm = b.package_manager.upper() if b.package_manager else "OS"
            if b.ssh_permit_root_login is not None or b.ssh_password_authentication is not None:
                self.console.print(
                    f"   SSH: PermitRootLogin={b.ssh_permit_root_login or 'unknown'}, "
                    f"PasswordAuthentication={b.ssh_password_authentication or 'unknown'}"
                )
            if b.pending_updates_total is not None:
                sec_str = (
                    f", security={b.pending_security_updates}"
                    if b.pending_security_updates is not None
                    else ""
                )
                self.console.print(f"   Updates ({pm}): total={b.pending_updates_total}{sec_str}")
            if b.reboot_required:
                self.console.print("   [yellow]! Reboot required[/]")

        health_issues = 0
        if findings:
            health_issues = sum(1 for f in findings if f.severity in (Severity.WARNING, Severity.CRITICAL))
        
        from server_doctor.model.server import ProjectType
        discovery_gaps = 0
        if model.projects:
            discovery_gaps = sum(1 for p in model.projects if p.confidence < 0.7 or p.type == ProjectType.UNKNOWN)

        if health_issues:
            self.console.print(f"   [yellow]! Projects with warnings/critical issues: {health_issues}[/]")
        if discovery_gaps:
            self.console.print(f"   [blue]i Projects with low-confidence/unknown: {discovery_gaps}[/]")

        # Build Info Footer
        if model.doctor_version:
            build_info = f"[dim]Server Doctor v{model.doctor_version}[/]"
            if model.commit_hash:
                build_info += f" [dim]({model.commit_hash})[/]"
            if model.scan_timestamp:
                build_info += f" [dim]• {model.scan_timestamp[:16].replace('T', ' ')}[/]"
            self.console.print(f"\n   {build_info}")

        if model.projects:
            table = Table(show_header=True)
            table.add_column("Project")
            table.add_column("Type")
            table.add_column("Confidence")
            table.add_column("PHP Socket")

            for p in model.projects:
                path_parts = p.path.strip("/").split("/")
                if len(path_parts) >= 2 and path_parts[0] == "var" and path_parts[1] == "www":
                    display_name = "/".join(path_parts[2:])
                elif len(path_parts) >= 2:
                    display_name = "/".join(path_parts[-2:])
                else:
                    display_name = path_parts[-1] if path_parts else p.path

                conf_style = "yellow" if p.confidence < 0.7 else "green"
                socket_display = p.php_socket.split("/")[-1] if p.php_socket else "[dim]—[/]"

                table.add_row(display_name, f"[{conf_style}]{p.type.value}[/]", f"[{conf_style}]{p.confidence:.0%}[/]", socket_display)

            self.console.print(table)

        self._report_telemetry(model)
        self._report_runtime_topology(model)
        self._report_upstream_probes(model)

    def _report_telemetry(self, model: ServerModel) -> None:
        """Report host telemetry snapshot."""
        t = model.telemetry
        if not t:
            return

        has_any_metric = (
            t.load_1 is not None
            or (t.mem_total_mb is not None and t.mem_available_mb is not None)
            or bool(t.disks)
        )
        if not has_any_metric:
            return

        table = Table(title="Host Telemetry", show_header=True, header_style="bold cyan")
        table.add_column("Metric")
        table.add_column("Value")

        if t.load_1 is not None:
            cores = t.cpu_cores if t.cpu_cores is not None else "?"
            table.add_row("Load (1/5/15)", f"{t.load_1:.2f} / {t.load_5:.2f} / {t.load_15:.2f} (cores={cores})")

        if t.mem_total_mb is not None and t.mem_available_mb is not None and t.mem_total_mb > 0:
            avail_pct = (t.mem_available_mb / t.mem_total_mb) * 100.0
            mem_color = "green" if avail_pct >= 20 else ("yellow" if avail_pct >= 10 else "red")
            table.add_row(
                "Memory Available",
                f"[{mem_color}]{t.mem_available_mb}MB / {t.mem_total_mb}MB ({avail_pct:.1f}%)[/]",
            )

        if t.swap_total_mb is not None and t.swap_free_mb is not None and t.swap_total_mb > 0:
            swap_used = t.swap_total_mb - t.swap_free_mb
            swap_used_pct = (swap_used / t.swap_total_mb) * 100.0
            swap_color = "green" if swap_used_pct < 80 else ("yellow" if swap_used_pct < 95 else "red")
            table.add_row(
                "Swap Used",
                f"[{swap_color}]{swap_used}MB / {t.swap_total_mb}MB ({swap_used_pct:.1f}%)[/]",
            )

        for disk in t.disks[:3]:
            disk_color = "green" if disk.used_percent < 85 else ("yellow" if disk.used_percent < 95 else "red")
            inode_suffix = ""
            if disk.inode_used_percent is not None:
                inode_color = "green" if disk.inode_used_percent < 85 else ("yellow" if disk.inode_used_percent < 95 else "red")
                inode_suffix = f", inode=[{inode_color}]{disk.inode_used_percent:.1f}%[/]"
            table.add_row(
                f"Disk {disk.mount}",
                f"[{disk_color}]{disk.used_percent:.1f}% ({disk.used_gb:.2f}GB/{disk.total_gb:.2f}GB)[/]{inode_suffix}",
            )

        self.console.print(table)
        self.console.print()

    def _report_runtime_topology(self, model: ServerModel) -> None:
        """Report runtime topology (Systemd, Redis, Workers)."""
        if not hasattr(model, "runtime"):
            return
            
        from rich.columns import Columns
        
        # Systemd Table
        if model.runtime.systemd_services:
            table = Table(title="Systemd Services", show_header=True, header_style="bold blue")
            table.add_column("Service")
            table.add_column("State")
            table.add_column("Restarts")
            
            for svc in model.runtime.systemd_services:
                state_color = "green" if svc.state == "active" else "red"
                restart_color = "green" if svc.restart_count < 5 else "red"
                table.add_row(
                    svc.name,
                    f"[{state_color}]{svc.state}[/]/[dim]{svc.substate}[/]",
                    f"[{restart_color}]{svc.restart_count}[/]"
                )
            self.console.print(table)
            self.console.print()

        # Redis Table
        if model.runtime.redis_instances:
            table = Table(title="Redis Instances", show_header=True, header_style="bold red")
            table.add_column("Port")
            table.add_column("Auth")
            table.add_column("Binding")
            
            for redis in model.runtime.redis_instances:
                auth_str = "Enabled" if redis.auth_enabled else ("Disabled" if redis.auth_enabled is False else "Unknown")
                auth_color = "green" if redis.auth_enabled else "red"
                bind_str = ", ".join(redis.bind_addresses)
                bind_color = "red" if "0.0.0.0" in bind_str or "::" in bind_str else "green"
                
                table.add_row(
                    str(redis.port),
                    f"[{auth_color}]{auth_str}[/]",
                    f"[{bind_color}]{bind_str}[/]"
                )
            self.console.print(table)
            self.console.print()

        # Workers Table
        if model.runtime.worker_processes:
            title = "Background Workers"
            if model.runtime.scheduler_detected:
                title += f" (Scheduler: {model.runtime.scheduler_type})"
            else:
                 title += " (Scheduler: [red]MISSING[/])"

            table = Table(title=title, show_header=True, header_style="bold magenta")
            table.add_column("PID")
            table.add_column("Type")
            table.add_column("Backend")
            table.add_column("Command", no_wrap=True)
            
            for w in model.runtime.worker_processes:
                cmd_display = w.cmdline
                if "artisan" in w.cmdline:
                     cmd_display = "artisan " + w.cmdline.split("artisan")[-1].strip()
                elif "node" in w.cmdline:
                     cmd_display = "node " + w.cmdline.split("node")[-1].strip()
                
                if len(cmd_display) > 50:
                    cmd_display = cmd_display[:47] + "..."

                table.add_row(
                    str(w.pid),
                    w.queue_type,
                    w.backend,
                    f"[dim]{cmd_display}[/]"
                )
            self.console.print(table)
            self.console.print()

    def report_wss_inventory(self, inventory: list) -> None:
        """Report WebSocket inventory."""
        if not inventory:
            return
            
        self.console.print()
        self.console.print(Panel.fit("🔌 WebSocket (WSS) Inventory", style="bold magenta"))
        self.console.print()
        
        table = Table(show_header=True, header_style="bold white", expand=True)
        table.add_column("Domain")
        table.add_column("Ports")
        table.add_column("WS Path")
        table.add_column("Proxy Target")
        table.add_column("Upgrade", justify="center")
        table.add_column("Risk", justify="center")
        
        for ws in inventory:
            risk_style = {
                "OK": "[green]OK[/]",
                "WARNING": "[yellow]WARN[/]",
                "CRITICAL": "[red]CRIT[/]",
            }.get(ws.risk_level, ws.risk_level)
            
            upgrade_icon = "[green]✓[/]" if ws.has_upgrade and ws.has_connection and ws.has_http_version_11 else "[red]✗[/]"
            
            table.add_row(
                ws.domain,
                ", ".join(ws.ports),
                ws.location.path,
                ws.proxy_target[:30] + "..." if len(ws.proxy_target) > 30 else ws.proxy_target,
                upgrade_icon,
                risk_style,
            )
        
        self.console.print(table)

    def _report_upstream_probes(self, model: ServerModel) -> None:
        probes = getattr(model, "upstream_probes", []) or []
        if not probes:
            return
        table = Table(title="Active Upstream Probes", show_header=True, header_style="bold green")
        table.add_column("Target")
        table.add_column("Status")
        table.add_column("TCP")
        table.add_column("HTTP")
        table.add_column("WS")
        table.add_column("Detail")
        for probe in probes:
            status = getattr(probe, "status", "UNKNOWN")
            ws = getattr(probe, "ws_status", None) or (str(getattr(probe, "ws_code", "")) if getattr(probe, "ws_code", None) is not None else "n/a")
            table.add_row(
                probe.target,
                status,
                "ok" if getattr(probe, "tcp_ok", None) else ("fail" if getattr(probe, "tcp_ok", None) is not None else "n/a"),
                str(getattr(probe, "http_code", None) if getattr(probe, "http_code", None) is not None else "n/a"),
                ws,
                getattr(probe, "ws_detail", None) or (probe.detail or ""),
            )
        self.console.print(table)
        self.console.print()
