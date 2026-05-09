from server_doctor.checks.laravel.production_auditor import LaravelProductionAuditor, LaravelProject


def test_laravel_debug_true_emits_redacted_finding():
    auditor = LaravelProductionAuditor()
    findings = auditor.audit_project(
        LaravelProject(
            path="/var/www/app",
            env_path="/var/www/app/.env",
            env_text="APP_DEBUG=true\nAPP_ENV=production",
        )
    )

    debug = [f for f in findings if f.id == "LARAVEL-PROD-001"][0]
    assert debug.evidence[0].excerpt == "APP_DEBUG=<redacted>"


def test_laravel_valid_env_does_not_emit():
    auditor = LaravelProductionAuditor()
    findings = auditor.audit_project(
        LaravelProject(
            path="/var/www/app",
            env_path="/var/www/app/.env",
            env_text="APP_DEBUG=false\nAPP_ENV=production",
        )
    )

    assert findings == []


def test_missing_env_does_not_leak_or_crash():
    auditor = LaravelProductionAuditor()
    assert auditor.audit_project(LaravelProject("/var/www/app", "/var/www/app/.env", None)) == []
