from pathlib import Path

from server_doctor.actions.report_bundle import ReportBundleAction
from server_doctor.model.evidence import Evidence, Severity
from server_doctor.model.finding import Finding
from server_doctor.model.server import ServerModel
from server_doctor.model.server import CertbotModel


def test_report_bundle_writes_expected_files(tmp_path: Path):
    model = ServerModel(
        hostname="host1",
        scan_timestamp="2026-02-11T12:00:00",
        doctor_version="1.8.0",
        certbot=CertbotModel(
            renew_dry_run_output="dry-run output",
            systemctl_status_output="systemctl status output",
        ),
    )
    findings = [
        Finding(
            id="SSH-1",
            severity=Severity.WARNING,
            confidence=0.9,
            condition="SSH password authentication is enabled",
            cause="cause",
            evidence=[Evidence(source_file="x", line_number=1, excerpt="PasswordAuthentication yes")],
            treatment="t",
            impact=["i"],
        )
    ]

    bundle = ReportBundleAction().export(
        bundle_dir=tmp_path / "bundle",
        model=model,
        findings=findings,
        trend={"has_previous": False},
        topology_snapshot={"signature": "abc123", "stats": {"routes": 1}},
        suppressed_findings=[{"id": "NGX-1", "reason": "accepted"}],
        html_report_path=str(tmp_path / "bundle" / "report.html"),
    )

    assert Path(bundle["summary"]).exists()
    assert Path(bundle["model"]).exists()
    assert Path(bundle["findings"]).exists()
    assert Path(bundle["trend"]).exists()
    assert Path(bundle["topology"]).exists()
    assert Path(bundle["waived_findings"]).exists()
    assert Path(bundle["certbot_renew_dry_run"]).exists()
    assert Path(bundle["certbot_systemctl_status"]).exists()

    summary = Path(bundle["summary"]).read_text(encoding="utf-8")
    assert "Host: host1" in summary
    assert "critical=0, warning=1, info=0" in summary
