"""Plain Text Reporter Implementation."""

from rich.console import Console
from rich.text import Text

from server_doctor.actions.reporters.base import BaseReporter
from server_doctor.model.evidence import Severity
from server_doctor.model.finding import Finding
from server_doctor.model.server import ServerModel


class PlainReporter(BaseReporter):
    """Generates clean, text-only output."""

    def report_findings(self, findings: list[Finding]) -> int:
        """Report diagnosis findings to the console."""
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

        self.console.print("DIAGNOSIS RESULTS", style="bold")
        self.console.print(f"Summary: {critical_count} critical, {warning_count} warning, {info_count} info")
        self.console.print()

        for finding in sorted_findings:
            self._print_finding(finding)

        return 1 if warning_count > 0 or critical_count > 0 else 0

    def _print_score_summary(self, findings: list[Finding]) -> None:
        """Print the 0-100 score card."""
        from server_doctor.engine.scoring import ScoringEngine
        scorer = ScoringEngine()
        score = scorer.calculate(findings)
        
        self.console.print(f"Server Health Score: {score.total}/100")
        self.console.print(f"Security: {score.security.current_points}/{score.security.max_points}")
        self.console.print(f"Performance: {score.performance.current_points}/{score.performance.max_points}")
        self.console.print(f"Architecture: {score.architecture.current_points}/{score.architecture.max_points}")
        self.console.print(f"Laravel/App: {score.app.current_points}/{score.app.max_points}")

    def _print_finding(self, finding: Finding) -> None:
        """Print a single finding."""
        severity_label = f"[{finding.severity.value.upper()}]"
        title = f"{finding.id}: {finding.condition}"
        if finding.derived_from:
            title += f" (derived_from={finding.derived_from})"
            
        self.console.print(f"{severity_label}: {title}")
        self.console.print(f"   Cause: {finding.cause}")
        self.console.print(f"   Confidence: {finding.confidence:.0%}")
        
        if finding.evidence:
            self.console.print("   Evidence:")
            for ev in finding.evidence:
                line = f"      - file={ev.source_file} line={ev.line_number}"
                if ev.excerpt:
                    clean_excerpt = ev.excerpt.replace('\n', ' ').strip()
                    line += f" excerpt=\"{clean_excerpt}\""
                self.console.print(line)

        if finding.treatment:
            self.console.print("   Treatment:")
            treatment_lines = str(finding.treatment).split('\n')
            for line in treatment_lines:
                self.console.print(f"      {line}")
        
        if finding.impact:
            self.console.print("   Impact if ignored:")
            for impact in finding.impact:
                self.console.print(f"      ! {impact}")

        if self.show_explain:
            from server_doctor.engine.knowledge_base import get_explanation
            expl = get_explanation(finding.id)
            if expl:
                self.console.print("   Explanation:")
                self.console.print(f"      Why: {expl.why}")
                self.console.print(f"      Risk: {expl.risk}")
                self.console.print(f"      When to ignore: {expl.ignore}")
        self.console.print()

    def report_server_summary(self, model: ServerModel, findings: list[Finding] | None = None) -> None:
        """Display server summary."""
        self.console.print(f"SERVER: {model.hostname}")

        if model.os:
            self.console.print(f"OS: {model.os.full_name}")
        if model.nginx:
            source_info = f"{model.nginx.mode}"
            if model.nginx.container_id:
                source_info += f" ({model.nginx.container_id[:12]})"
            self.console.print(f"Nginx: {model.nginx.version} (Source: {source_info})")
        if model.php:
            self.console.print(f"PHP: {', '.join(model.php.versions)}")
        if model.telemetry:
            t = model.telemetry
            if t.load_1 is not None:
                cores = t.cpu_cores if t.cpu_cores is not None else "?"
                self.console.print(f"Load: {t.load_1:.2f} / {t.load_5:.2f} / {t.load_15:.2f} (cores: {cores})")
            if t.mem_total_mb is not None and t.mem_available_mb is not None:
                self.console.print(f"Memory: {t.mem_available_mb}MB available / {t.mem_total_mb}MB total")
            if t.disks:
                top_disk = t.disks[0]
                inode_suffix = ""
                if top_disk.inode_used_percent is not None:
                    inode_suffix = f", inode {top_disk.inode_used_percent:.1f}%"
                self.console.print(
                    f"Disk: {top_disk.mount} {top_disk.used_percent:.1f}% ({top_disk.used_gb:.2f}GB/{top_disk.total_gb:.2f}GB{inode_suffix})"
                )
        if model.security_baseline:
            b = model.security_baseline
            pm = b.package_manager.upper() if b.package_manager else "OS"
            if b.ssh_permit_root_login is not None or b.ssh_password_authentication is not None:
                self.console.print(
                    f"SSH: PermitRootLogin={b.ssh_permit_root_login or 'unknown'}, "
                    f"PasswordAuthentication={b.ssh_password_authentication or 'unknown'}"
                )
            if b.pending_updates_total is not None:
                sec_part = (
                    f", security={b.pending_security_updates}"
                    if b.pending_security_updates is not None
                    else ""
                )
                self.console.print(f"Updates ({pm}): total={b.pending_updates_total}{sec_part}")
            if b.reboot_required:
                self.console.print("Reboot Required: yes")
        if model.vulnerability:
            v = model.vulnerability
            if v.provider != "unknown" or v.cve_ids or v.advisory_ids:
                self.console.print(
                    f"Vulnerability Posture: provider={v.provider}, "
                    f"cves={len(v.cve_ids)}, advisories={len(v.advisory_ids)}, "
                    f"packages={len(v.affected_packages)}"
                )
        if model.network_surface and model.network_surface.endpoints:
            public_eps = [ep for ep in model.network_surface.endpoints if ep.public_exposed]
            self.console.print(
                f"Network Surface: endpoints={len(model.network_surface.endpoints)}, "
                f"public={len(public_eps)}"
            )

        if model.projects:
            self.console.print("\nPROJECTS:")
            for p in model.projects:
                self.console.print(f"- {p.path} ({p.type.value}) [Conf: {p.confidence:.0%}]")
        self._report_upstream_probes(model)

    def report_wss_inventory(self, inventory: list) -> None:
        """Report WebSocket inventory."""
        if not inventory:
            return
            
        self.console.print("\nWEBSOCKET (WSS) INVENTORY")
        for ws in inventory:
            status = "OK" if ws.risk_level == "OK" else ws.risk_level
            self.console.print(f"[{status}] {ws.domain}:{','.join(ws.ports)} {ws.location.path}")
            self.console.print(f"   Target: {ws.proxy_target}")
            self.console.print(f"   Upgrade: {'Yes' if ws.has_upgrade else 'No'}, Connection: {'Yes' if ws.has_connection else 'No'}")
            if ws.issues:
                self.console.print(f"   Issues: {', '.join(ws.issues)}")
            self.console.print()

    def _report_upstream_probes(self, model: ServerModel) -> None:
        probes = getattr(model, "upstream_probes", []) or []
        if not probes:
            return
        self.console.print("\nACTIVE UPSTREAM PROBES")
        for probe in probes:
            ws_status = getattr(probe, "ws_status", None) or (
                str(getattr(probe, "ws_code", "")) if getattr(probe, "ws_code", None) is not None else "n/a"
            )
            self.console.print(
                f"- {probe.target} [{probe.status}] tcp="
                f"{'ok' if getattr(probe, 'tcp_ok', None) else ('fail' if getattr(probe, 'tcp_ok', None) is not None else 'n/a')} "
                f"http={getattr(probe, 'http_code', None) if getattr(probe, 'http_code', None) is not None else 'n/a'} "
                f"ws={ws_status}"
            )
            if getattr(probe, "ws_detail", None):
                self.console.print(f"    ws_detail: {probe.ws_detail}")
