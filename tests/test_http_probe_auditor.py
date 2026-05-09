from server_doctor.analyzer.http_probe_auditor import HttpProbeAuditor
from server_doctor.model.server import HttpProbeModel, HttpProbeResult, ServerModel


def _result(url, status, body="", error=None, final_url=None):
    return HttpProbeResult(
        url=url,
        method="GET",
        status_code=status,
        final_url=final_url or url,
        redirect_chain=[],
        headers={},
        body_sample=body,
        error=error,
        elapsed_ms=10,
    )


def test_https_502_emits_upstream_failure():
    model = ServerModel(
        hostname="example.com",
        http_probes=HttpProbeModel(results=[_result("https://example.com", 502)]),
    )

    findings = HttpProbeAuditor(model).audit()

    assert any(f.id == "HTTP-PROBE-007" for f in findings)
    assert findings[0].evidence


def test_env_403_does_not_emit_exposure():
    model = ServerModel(
        hostname="example.com",
        http_probes=HttpProbeModel(results=[_result("https://example.com/.env", 403)]),
    )

    assert not HttpProbeAuditor(model).audit()


def test_redirect_loop_emits_without_infinite_loop():
    model = ServerModel(
        hostname="example.com",
        http_probes=HttpProbeModel(
            results=[_result("https://example.com", None, error="redirect_loop")]
        ),
    )

    findings = HttpProbeAuditor(model).audit()

    assert [f.id for f in findings] == ["HTTP-PROBE-002"]


def test_composer_json_real_body_emits_critical_exposure():
    model = ServerModel(
        hostname="example.com",
        http_probes=HttpProbeModel(
            results=[
                _result(
                    "https://example.com/composer.json",
                    200,
                    '{"require":{"laravel/framework":"^11.0"},"autoload":{}}',
                )
            ]
        ),
    )

    findings = HttpProbeAuditor(model).audit()

    assert [f.id for f in findings] == ["HTTP-PROBE-005"]
    assert findings[0].severity.value == "critical"


def test_composer_json_spa_fallback_emits_soft_404_not_critical():
    model = ServerModel(
        hostname="example.com",
        http_probes=HttpProbeModel(
            results=[
                _result(
                    "https://example.com/composer.json",
                    200,
                    '<!doctype html><div id="root"></div><script type="module"></script>',
                )
            ]
        ),
    )

    findings = HttpProbeAuditor(model).audit()

    assert [f.id for f in findings] == ["HTTP-PROBE-SOFT404"]
    assert findings[0].severity.value == "warning"


def test_env_spa_fallback_emits_soft_404_not_critical():
    model = ServerModel(
        hostname="example.com",
        http_probes=HttpProbeModel(
            results=[
                _result(
                    "https://example.com/.env",
                    200,
                    '<html><body><div id="root"></div></body></html>',
                )
            ]
        ),
    )

    findings = HttpProbeAuditor(model).audit()

    assert [f.id for f in findings] == ["HTTP-PROBE-SOFT404"]


def test_git_config_real_body_emits_critical_exposure():
    model = ServerModel(
        hostname="example.com",
        http_probes=HttpProbeModel(
            results=[
                _result(
                    "https://example.com/.git/config",
                    200,
                    "[core]\nrepositoryformatversion = 0\nfilemode = true\n",
                )
            ]
        ),
    )

    findings = HttpProbeAuditor(model).audit()

    assert [f.id for f in findings] == ["HTTP-PROBE-005"]


def test_sensitive_path_404_emits_no_finding():
    model = ServerModel(
        hostname="example.com",
        http_probes=HttpProbeModel(
            results=[_result("https://example.com/composer.json", 404)]
        ),
    )

    assert not HttpProbeAuditor(model).audit()
