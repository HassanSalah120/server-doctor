"""JSON Reporter Implementation."""

import json
from dataclasses import asdict
from rich.console import Console

from server_doctor.actions.reporters.base import BaseReporter
from server_doctor.model.evidence import Severity
from server_doctor.model.finding import Finding
from server_doctor.model.server import ServerModel


class JsonReporter(BaseReporter):
    """Generates machine-readable JSON output."""

    def report_findings(self, findings: list[Finding]) -> int:
        """Report diagnosis findings to the console."""
        data = [asdict(f) for f in findings]
        for item, finding in zip(data, findings):
            item['severity'] = item['severity'].value if hasattr(item['severity'], 'value') else str(item['severity'])
            item['evidence'] = [asdict(e) for e in finding.evidence]
        
        self.console.print(json.dumps(data, indent=2))
        return 1 if any(f.severity in (Severity.CRITICAL, Severity.WARNING) for f in findings) else 0

    def report_server_summary(self, model: ServerModel, findings: list[Finding] | None = None) -> None:
        """Display server summary as JSON."""
        # For JSON, usually we might just dump the model
        data = asdict(model)
        self.console.print(json.dumps(data, indent=2, default=str))

    def report_wss_inventory(self, inventory: list) -> None:
        """Report WebSocket inventory as JSON."""
        data = [
            {
                "domain": ws.domain,
                "ports": ws.ports,
                "path": ws.location.path,
                "proxy_target": ws.proxy_target,
                "has_upgrade": ws.has_upgrade,
                "has_connection": ws.has_connection,
                "has_http_version_11": ws.has_http_version_11,
                "buffering": ws.buffering,
                "read_timeout": ws.read_timeout,
                "risk_level": ws.risk_level,
                "issues": ws.issues,
            }
            for ws in inventory
        ]
        self.console.print(json.dumps(data, indent=2))
