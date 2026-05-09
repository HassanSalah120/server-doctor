"""Export bundle artifacts for a diagnose run."""

from __future__ import annotations

import json
from dataclasses import asdict
from enum import Enum
from pathlib import Path

from server_doctor.model.finding import Finding
from server_doctor.model.server import ServerModel
from server_doctor.utils.redaction import redact_text, redact_value


class ReportBundleAction:
    """Writes companion report artifacts alongside HTML report."""

    def export(
        self,
        bundle_dir: str | Path,
        model: ServerModel,
        findings: list[Finding],
        trend: dict | None = None,
        topology_snapshot: dict | None = None,
        suppressed_findings: list[dict] | None = None,
        html_report_path: str | None = None,
    ) -> dict[str, str]:
        out_dir = Path(bundle_dir).expanduser()
        out_dir.mkdir(parents=True, exist_ok=True)

        model_path = out_dir / "model.json"
        findings_path = out_dir / "findings.json"
        summary_path = out_dir / "summary.txt"
        trend_path = out_dir / "trend.json"
        topology_path = out_dir / "topology.json"
        waived_path = out_dir / "waived_findings.json"
        certbot_dry_run_path = out_dir / "certbot_renew_dry_run.txt"
        certbot_systemctl_path = out_dir / "certbot_systemctl_status.txt"
        certbot_journal_path = out_dir / "certbot_journal.txt"
        certbot_unit_cat_path = out_dir / "certbot_systemctl_cat.txt"
        certbot_certs_path = out_dir / "certbot_certificates.txt"
        certbot_renewal_ls_path = out_dir / "certbot_renewal_ls.txt"

        model_payload = redact_value(asdict(model))
        findings_payload = redact_value([asdict(finding) for finding in findings])

        model_path.write_text(
            json.dumps(model_payload, indent=2, default=self._json_default),
            encoding="utf-8",
        )
        findings_path.write_text(
            json.dumps(findings_payload, indent=2, default=self._json_default),
            encoding="utf-8",
        )

        summary_path.write_text(
            self._build_summary(model, findings, html_report_path=html_report_path),
            encoding="utf-8",
        )

        written = {
            "model": str(model_path.resolve()),
            "findings": str(findings_path.resolve()),
            "summary": str(summary_path.resolve()),
        }

        if trend is not None:
            trend_path.write_text(
                json.dumps(redact_value(trend), indent=2, default=self._json_default),
                encoding="utf-8",
            )
            written["trend"] = str(trend_path.resolve())

        if topology_snapshot is not None:
            topology_path.write_text(
                json.dumps(redact_value(topology_snapshot), indent=2, default=self._json_default),
                encoding="utf-8",
            )
            written["topology"] = str(topology_path.resolve())

        if suppressed_findings:
            waived_path.write_text(
                json.dumps(redact_value(suppressed_findings), indent=2, default=self._json_default),
                encoding="utf-8",
            )
            written["waived_findings"] = str(waived_path.resolve())

        certbot = getattr(model, "certbot", None)
        if certbot and getattr(certbot, "renew_dry_run_output", None):
            certbot_dry_run_path.write_text(redact_text(certbot.renew_dry_run_output or ""), encoding="utf-8")
            written["certbot_renew_dry_run"] = str(certbot_dry_run_path.resolve())
        if certbot and getattr(certbot, "systemctl_status_output", None):
            certbot_systemctl_path.write_text(redact_text(certbot.systemctl_status_output or ""), encoding="utf-8")
            written["certbot_systemctl_status"] = str(certbot_systemctl_path.resolve())
        if certbot and getattr(certbot, "journal_output", None):
            certbot_journal_path.write_text(redact_text(certbot.journal_output or ""), encoding="utf-8")
            written["certbot_journal"] = str(certbot_journal_path.resolve())
        if certbot and getattr(certbot, "unit_cat_output", None):
            certbot_unit_cat_path.write_text(redact_text(certbot.unit_cat_output or ""), encoding="utf-8")
            written["certbot_systemctl_cat"] = str(certbot_unit_cat_path.resolve())
        if certbot and getattr(certbot, "certificates_output", None):
            certbot_certs_path.write_text(redact_text(certbot.certificates_output or ""), encoding="utf-8")
            written["certbot_certificates"] = str(certbot_certs_path.resolve())
        if certbot and getattr(certbot, "renewal_dir_listing", None):
            certbot_renewal_ls_path.write_text(redact_text(certbot.renewal_dir_listing or ""), encoding="utf-8")
            written["certbot_renewal_ls"] = str(certbot_renewal_ls_path.resolve())

        return written

    @staticmethod
    def _json_default(obj: object) -> str:
        if isinstance(obj, Enum):
            return obj.value
        return str(obj)

    def _build_summary(self, model: ServerModel, findings: list[Finding], html_report_path: str | None = None) -> str:
        critical = sum(1 for finding in findings if finding.severity.value == "critical")
        warning = sum(1 for finding in findings if finding.severity.value == "warning")
        info = sum(1 for finding in findings if finding.severity.value == "info")

        lines = [
            f"Host: {model.hostname}",
            f"Scan Timestamp: {model.scan_timestamp or 'unknown'}",
            f"Server Doctor Version: {model.doctor_version or 'unknown'}",
            f"Commit: {model.commit_hash or 'unknown'}",
            f"Findings: critical={critical}, warning={warning}, info={info}",
        ]
        if html_report_path:
            lines.append(f"HTML Report: {html_report_path}")
        lines.append("")
        lines.append("Top Findings:")
        for finding in findings[:10]:
            lines.append(f"- [{finding.severity.value.upper()}] {finding.id}: {finding.condition}")
        lines.append("")
        return "\n".join(lines)
