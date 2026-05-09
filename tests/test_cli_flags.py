"""Tests for CLI flags and HTML output helpers."""

from contextlib import ExitStack
from pathlib import Path
import sys
from unittest.mock import MagicMock, patch

from click.testing import CliRunner

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from server_doctor.cli import _resolve_html_output_path, _scan_time_label, diagnose


AUDITOR_PATCH_TARGETS = [
    "server_doctor.cli.ServerAuditor",
    "server_doctor.analyzer.wss_auditor.WSSAuditor",
    "server_doctor.analyzer.docker_auditor.DockerAuditor",
    "server_doctor.analyzer.node_auditor.NodeAuditor",
    "server_doctor.analyzer.systemd_auditor.SystemdAuditor",
    "server_doctor.analyzer.redis_auditor.RedisAuditor",
    "server_doctor.analyzer.worker_auditor.WorkerAuditor",
    "server_doctor.analyzer.mysql_auditor.MySQLAuditor",
    "server_doctor.analyzer.firewall_auditor.FirewallAuditor",
    "server_doctor.analyzer.telemetry_auditor.TelemetryAuditor",
    "server_doctor.analyzer.security_baseline_auditor.SecurityBaselineAuditor",
    "server_doctor.analyzer.vulnerability_auditor.VulnerabilityAuditor",
    "server_doctor.analyzer.network_surface_auditor.NetworkSurfaceAuditor",
]


def _make_server_model():
    from server_doctor.model.server import (
        CapabilityLevel,
        NginxInfo,
        PHPInfo,
        ServerModel,
        ServiceStatus,
    )

    return ServerModel(
        hostname="example.com",
        nginx=NginxInfo(version="1.24.0", config_path="/etc/nginx/nginx.conf"),
        php=PHPInfo(versions=["8.2"]),
        nginx_status=ServiceStatus(capability=CapabilityLevel.FULL),
    )


def _mock_diagnose_context(stack: ExitStack):
    mocks: dict[str, MagicMock] = {}
    mocks["resolve"] = stack.enter_context(patch("server_doctor.cli._resolve_config"))
    mocks["scan"] = stack.enter_context(patch("server_doctor.cli._scan_server"))
    mocks["ssh"] = stack.enter_context(patch("server_doctor.cli.SSHConnector"))
    mocks["doctor"] = stack.enter_context(patch("server_doctor.cli.ServerDoctorAnalyzer"))
    mocks["run_checks"] = stack.enter_context(patch("server_doctor.checks.run_checks"))

    for target in AUDITOR_PATCH_TARGETS:
        mocks[target] = stack.enter_context(patch(target))

    mocks["resolve"].return_value = MagicMock()
    mocks["scan"].return_value = _make_server_model()
    mocks["doctor"].return_value.diagnose.return_value = []
    mocks["run_checks"].return_value = []

    for target in AUDITOR_PATCH_TARGETS:
        patched = mocks[target]
        patched.return_value.audit.return_value = []
        if target.endswith("WSSAuditor"):
            patched.return_value.get_inventory.return_value = []

    return mocks


def test_score_flag():
    """Verify --score passes true to ReportAction."""
    runner = CliRunner()

    with ExitStack() as stack:
        _mock_diagnose_context(stack)
        reporter = stack.enter_context(patch("server_doctor.cli.ReportAction"))

        result = runner.invoke(diagnose, ["myserver", "--score", "--format", "rich"])

        assert result.exit_code == 0
        assert reporter.called
        _, kwargs = reporter.call_args
        assert kwargs.get("show_score") is True


def test_explain_flag():
    """Verify --explain passes true to ReportAction."""
    runner = CliRunner()

    with ExitStack() as stack:
        _mock_diagnose_context(stack)
        reporter = stack.enter_context(patch("server_doctor.cli.ReportAction"))

        result = runner.invoke(diagnose, ["myserver", "--explain", "--format", "rich"])

        assert result.exit_code == 0
        assert reporter.called
        _, kwargs = reporter.call_args
        assert kwargs.get("show_explain") is True


def test_safe_fix_trigger():
    """Verify --safe-fix triggers SafeFixAction."""
    runner = CliRunner()

    with ExitStack() as stack:
        mocks = _mock_diagnose_context(stack)
        report_action = stack.enter_context(patch("server_doctor.cli.ReportAction"))
        fixer = stack.enter_context(patch("server_doctor.cli.SafeFixAction"))

        from server_doctor.model.evidence import Evidence, Severity
        from server_doctor.model.finding import Finding

        report_action.return_value.report_findings.return_value = 0
        mocks["run_checks"].return_value = [
            Finding(
                id="TEST-1",
                severity=Severity.INFO,
                confidence=1.0,
                condition="test",
                cause="test",
                treatment="test",
                impact=["test"],
                evidence=[Evidence(source_file="test", line_number=1, excerpt="test")],
            )
        ]
        fixer.return_value.run.return_value = []

        result = runner.invoke(
            diagnose,
            ["myserver", "--safe-fix", "--dry-run", "--format", "rich"],
            obj={},
        )

        assert result.exit_code == 0
        fixer.assert_called()
        fixer.return_value.run.assert_called()


def test_optional_checks_enabled_by_default():
    """Diagnose should run modular checks by default unless --minimal is set."""
    runner = CliRunner()

    with ExitStack() as stack:
        mocks = _mock_diagnose_context(stack)

        result = runner.invoke(diagnose, ["myserver", "--format", "rich"])

        assert result.exit_code == 0
        ctx = mocks["run_checks"].call_args.args[0]
        assert ctx.laravel_enabled is True
        assert ctx.ports_enabled is True
        assert ctx.security_enabled is True
        assert ctx.phpfpm_enabled is True
        assert ctx.performance_enabled is True


def test_minimal_mode_allows_selective_opt_in():
    """--minimal should disable optional checks unless explicitly enabled."""
    runner = CliRunner()

    with ExitStack() as stack:
        mocks = _mock_diagnose_context(stack)

        result = runner.invoke(diagnose, ["myserver", "--minimal", "--ports", "--format", "rich"])

        assert result.exit_code == 0
        ctx = mocks["run_checks"].call_args.args[0]
        assert ctx.laravel_enabled is False
        assert ctx.ports_enabled is True
        assert ctx.security_enabled is False
        assert ctx.phpfpm_enabled is False
        assert ctx.performance_enabled is False


def test_diagnose_defaults_to_html_output():
    """Diagnose should default to HTML report mode when no format/interactive flags are set."""
    runner = CliRunner()

    with ExitStack() as stack:
        _mock_diagnose_context(stack)
        html_report = stack.enter_context(patch("server_doctor.cli.HTMLReportAction"))
        report_bundle = stack.enter_context(patch("server_doctor.cli.ReportBundleAction"))

        html_report.return_value.generate.return_value = "report.html"
        report_bundle.return_value.export.return_value = {
            "summary": "summary.txt",
            "model": "model.json",
            "findings": "findings.json",
        }

        result = runner.invoke(diagnose, ["myserver"])

        assert result.exit_code == 0
        html_report.assert_called_once()
        html_report.return_value.generate.assert_called_once()
        report_bundle.assert_called_once()

        _, kwargs = html_report.return_value.generate.call_args
        assert "reports" in kwargs.get("output_path", "")
        assert "example.com" in kwargs.get("output_path", "")


def test_scan_time_label_is_day_month_year():
    label = _scan_time_label("2026-02-11T14:45:39")
    assert label == "11-02-2026"


def test_default_html_output_path_uses_date_only_folder():
    path = _resolve_html_output_path(
        output=None,
        hostname="example.com",
        scan_timestamp="2026-02-11T14:45:39",
    )
    assert path == Path("reports") / "example.com" / "11-02-2026" / "report.html"
