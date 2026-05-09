"""Tests for PerformanceAuditor HTTP/2 detection."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from server_doctor.checks import CheckContext
from server_doctor.checks.performance.performance_auditor import PerformanceAuditor
from server_doctor.model.server import NginxInfo, ServerBlock, ServerModel


def _run_http2_check(server: ServerBlock) -> set[str]:
    model = ServerModel(
        hostname="example.com",
        nginx=NginxInfo(
            version="1.29.3",
            config_path="/etc/nginx/nginx.conf",
            servers=[server],
            raw="",
        ),
    )
    ctx = CheckContext(model=model, ssh=None)
    findings = PerformanceAuditor().run(ctx)
    return {f.id for f in findings}


def test_http2_enabled_via_listen_directive_not_flagged():
    server = ServerBlock(
        server_names=["example.com"],
        listen=["443 ssl http2"],
        ssl_enabled=True,
        source_file="/etc/nginx/conf.d/default.conf",
        line_number=10,
    )
    assert "NGX-PERF-2" not in _run_http2_check(server)


def test_http2_enabled_via_http2_on_not_flagged():
    server = ServerBlock(
        server_names=["example.com"],
        listen=["443 ssl"],
        ssl_enabled=True,
        http2_enabled=True,
        source_file="/etc/nginx/conf.d/default.conf",
        line_number=10,
    )
    assert "NGX-PERF-2" not in _run_http2_check(server)


def test_http2_missing_on_ssl_server_is_flagged():
    server = ServerBlock(
        server_names=["example.com"],
        listen=["443 ssl"],
        ssl_enabled=True,
        source_file="/etc/nginx/conf.d/default.conf",
        line_number=10,
    )
    assert "NGX-PERF-2" in _run_http2_check(server)

