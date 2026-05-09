from server_doctor.analyzer.redis_deep_auditor import RedisDeepAuditor
from server_doctor.model.server import (
    NetworkEndpoint,
    NetworkSurfaceModel,
    RedisDeepModel,
    ServerModel,
)


def test_public_redis_endpoint_emits():
    model = ServerModel(
        hostname="host",
        network_surface=NetworkSurfaceModel(
            endpoints=[NetworkEndpoint(protocol="tcp", address="0.0.0.0", port=6379)]
        ),
    )

    assert RedisDeepAuditor(model).audit()[0].id == "REDIS-DEEP-001"


def test_localhost_redis_endpoint_does_not_emit_public_exposure():
    model = ServerModel(
        hostname="host",
        network_surface=NetworkSurfaceModel(
            endpoints=[NetworkEndpoint(protocol="tcp", address="127.0.0.1", port=6379)]
        ),
    )

    assert not RedisDeepAuditor(model).audit()


def test_app_requires_redis_scanner_unavailable_warning_not_critical():
    from server_doctor.model.server import LaravelRuntimeModel, LaravelRuntimeProject

    model = ServerModel(
        hostname="host",
        laravel_runtime=LaravelRuntimeModel(
            projects=[LaravelRuntimeProject(path="/app", env={"QUEUE_CONNECTION": "redis"})]
        ),
        redis_deep=RedisDeepModel(scanner_available=False),
    )

    finding = RedisDeepAuditor(model).audit()[0]
    assert finding.id == "REDIS-DEEP-008"
    assert finding.severity.value == "warning"
