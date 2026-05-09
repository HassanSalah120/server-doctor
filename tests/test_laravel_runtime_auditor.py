from server_doctor.analyzer.laravel_runtime_auditor import LaravelRuntimeAuditor
from server_doctor.model.server import LaravelRuntimeModel, LaravelRuntimeProject, ServerModel


def test_redis_queue_without_worker_emits():
    project = LaravelRuntimeProject(
        path="/var/www/app",
        env_path="/var/www/app/.env",
        env={"QUEUE_CONNECTION": "redis", "APP_KEY": "base64:key"},
        queue_worker_running=False,
    )
    model = ServerModel(hostname="host", laravel_runtime=LaravelRuntimeModel(projects=[project]))

    findings = LaravelRuntimeAuditor(model).audit()

    assert any(f.id == "LARAVEL-RUNTIME-001" for f in findings)
    assert all(
        "redis" not in ev.excerpt.lower() or "<redacted>" in ev.excerpt
        for f in findings
        for ev in f.evidence
    )


def test_sync_queue_does_not_emit_worker_finding():
    project = LaravelRuntimeProject(
        path="/var/www/app",
        env={"QUEUE_CONNECTION": "sync", "APP_KEY": "base64:key"},
        queue_worker_running=False,
    )
    model = ServerModel(hostname="host", laravel_runtime=LaravelRuntimeModel(projects=[project]))

    findings = LaravelRuntimeAuditor(model).audit()

    assert not any(f.id == "LARAVEL-RUNTIME-001" for f in findings)


def test_unreadable_env_emits_capability_note_without_secret():
    project = LaravelRuntimeProject(path="/var/www/app", env_readable=False)
    model = ServerModel(hostname="host", laravel_runtime=LaravelRuntimeModel(projects=[project]))

    findings = LaravelRuntimeAuditor(model).audit()

    assert [f.id for f in findings] == ["LARAVEL-RUNTIME-CAPABILITY"]
    assert "password" not in findings[0].evidence[0].excerpt.lower()
