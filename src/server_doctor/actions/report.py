"""Report Action - Generate diagnostic reports using Strategy Pattern.

CONTRACT:
- read_only: True
- requires_backup: False
- rollback_support: N/A
- prerequisites: None
"""

from dataclasses import dataclass
from rich.console import Console

from server_doctor.actions.reporters.base import BaseReporter
from server_doctor.actions.reporters.rich_reporter import RichReporter
from server_doctor.actions.reporters.plain_reporter import PlainReporter
from server_doctor.actions.reporters.json_reporter import JsonReporter
from server_doctor.model.finding import Finding
from server_doctor.model.server import ServerModel
from server_doctor.engine.decision import Recommendation


@dataclass
class ActionContract:
    """Explicit contract for an action."""
    read_only: bool
    requires_backup: bool
    rollback_support: bool
    prerequisites: list[str]


class ReportAction:
    """Orchestrates diagnostic reporting using different strategies."""

    CONTRACT = ActionContract(
        read_only=True,
        requires_backup=False,
        rollback_support=False,
        prerequisites=[],
    )

    def __init__(self, console: Console | None = None, format_mode: str = "rich", no_wrap: bool = False, show_score: bool = False, show_explain: bool = False) -> None:
        self.console = console or Console()
        self.format_mode = format_mode
        self.show_score = show_score
        self.show_explain = show_explain
        
        # Factory: Select reporter strategy
        self._reporter: BaseReporter
        if format_mode == "json":
            self._reporter = JsonReporter(self.console, show_score, show_explain)
        elif format_mode == "plain":
            self._reporter = PlainReporter(self.console, show_score, show_explain)
        else:
            self._reporter = RichReporter(self.console, show_score, show_explain)

    def report_findings(self, findings: list[Finding]) -> int:
        """Report diagnosis findings."""
        return self._reporter.report_findings(findings)

    def report_server_summary(self, model: ServerModel, findings: list[Finding] | None = None) -> None:
        """Display server summary."""
        self._reporter.report_server_summary(model, findings)

    def report_wss_inventory(self, inventory: list) -> None:
        """Report WebSocket inventory."""
        self._reporter.report_wss_inventory(inventory)

    def report_inventory(self, inventory: list, base: str) -> None:
        """Report filesystem inventory."""
        if self.format_mode == "json":
            return
            
        self.console.print(f"\n[bold]Filesystem Inventory[/] (scanned {base})")
        self.console.print()
        
        configured = [item for item in inventory if item["status"] == "configured"]
        unreferenced = [item for item in inventory if item["status"] == "unreferenced"]
        
        if configured:
            self.console.print(f"[green]✓ Configured projects:[/] {len(configured)}")
            for item in configured:
                self.console.print(f"  • {item['path']} ({item['type'].value})")
        
        if unreferenced:
            self.console.print(f"[yellow]⚠ Unreferenced projects:[/] {len(unreferenced)}")
            for item in unreferenced:
                self.console.print(f"  • {item['path']} ({item['type'].value})")

    def report_recommendations(self, recommendations: list[Recommendation]) -> None:
        """Display recommendations (Legacy bridge or move to strategies if needed)."""
        # For now, keeping legacy logic in here or moving it to base/concrete
        # Recommendations are slightly different across modes too
        if self.format_mode == "json":
            return
            
        if self.format_mode == "plain":
            self.console.print("\nRecommendations:")
            for rec in recommendations:
                self.console.print(f"\n* {rec.summary}")
                for sol in rec.solutions:
                    self.console.print(f"  - [{sol.rank.value.upper()}] {sol.description}")
                    if sol.steps:
                        for i, step in enumerate(sol.steps, 1):
                            self.console.print(f"      {i}. {step}")
            return

        from rich.panel import Panel
        self.console.print()
        self.console.print(Panel.fit("Recommendations", style="bold yellow"))
        self.console.print()

        for rec in recommendations:
            self.console.print(f"[bold]{rec.summary}[/]")
            for solution in rec.solutions:
                rank_colors = {"best": "green", "acceptable": "yellow", "risky": "red"}
                color = rank_colors.get(solution.rank.value, "white")
                self.console.print(f"   [{color}]{solution.rank.value.upper()}[/]: {solution.description}")
                if solution.steps:
                    for i, step in enumerate(solution.steps, 1):
                        self.console.print(f"      {i}. {step}")
            self.console.print()

    def export_server_model(self, model: ServerModel, format: str) -> None:
        """Direct export (bypasses standard report flow)."""
        import dataclasses
        import json
        data = dataclasses.asdict(model)
        if format == "json":
            self.console.print(json.dumps(data, indent=2, default=str))
        elif format == "yaml":
            import yaml
            self.console.print(yaml.dump(data, sort_keys=False))

    def export_findings(self, findings: list[Finding], format: str) -> None:
        """Direct export (bypasses standard report flow)."""
        import dataclasses
        import json
        data = [dataclasses.asdict(f) for f in findings]
        if format == "json":
            self.console.print(json.dumps(data, indent=2, default=str))
        elif format == "yaml":
            import yaml
            self.console.print(yaml.dump(data, sort_keys=False))

    def _find_php_socket_for_project(self, model: ServerModel, project_path: str) -> str | None:
        """Find the FPM socket used by a specific project path."""
        if not model.nginx:
            return None
            
        # Standardize project path for comparison
        project_path = project_path.rstrip("/")
        
        for server in model.nginx.servers:
            # Check if this server block's root matches or contains the project path
            if server.root:
                srv_root = server.root.rstrip("/")
                if project_path == srv_root or srv_root.startswith(project_path + "/") or project_path.startswith(srv_root + "/"):
                    # Look for fastcgi_pass in locations
                    for loc in server.locations:
                        if loc.fastcgi_pass:
                            return loc.fastcgi_pass
            
            # Also check locations with their own roots
            for loc in server.locations:
                if loc.root:
                    loc_root = loc.root.rstrip("/")
                    if project_path == loc_root or loc_root.startswith(project_path + "/") or project_path.startswith(loc_root + "/"):
                        if loc.fastcgi_pass:
                            return loc.fastcgi_pass
                # Special case: location matching project path directly
                if loc.path == "/" or loc.path == project_path or project_path.endswith(loc.path):
                    if loc.fastcgi_pass:
                        return loc.fastcgi_pass
        return None
