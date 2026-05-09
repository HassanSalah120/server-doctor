"""Redis safety and runtime diagnosis."""

from __future__ import annotations

from server_doctor.model.evidence import Evidence, Severity
from server_doctor.model.finding import Finding
from server_doctor.model.server import NetworkEndpoint, RedisInstance, ServerModel


class RedisDeepAuditor:
    def __init__(self, model: ServerModel) -> None:
        self.model = model

    def audit(self) -> list[Finding]:
        findings: list[Finding] = []
        for endpoint in getattr(self.model.network_surface, "endpoints", []) or []:
            if is_redis_public(endpoint):
                findings.append(_finding(
                    "REDIS-DEEP-001",
                    Severity.CRITICAL,
                    "Redis is publicly exposed",
                    f"Redis TCP port {endpoint.port} is reachable publicly.",
                    f"{endpoint.protocol}/{endpoint.port} public",
                ))
        for instance in self.model.redis_deep.instances:
            if _instance_public(instance):
                findings.append(_finding(
                    "REDIS-DEEP-001",
                    Severity.CRITICAL,
                    "Redis is publicly exposed",
                    f"Redis binds to public addresses on port {instance.port}.",
                    f"bind={','.join(instance.bind_addresses)} port={instance.port}",
                ))
            if instance.protected_mode is False and _instance_public(instance):
                findings.append(_finding(
                    "REDIS-DEEP-002",
                    Severity.CRITICAL,
                    "Redis protected-mode is disabled",
                    "A public Redis instance has protected-mode disabled.",
                    "protected-mode no",
                ))
            if instance.auth_enabled is False and _instance_public(instance):
                findings.append(_finding(
                    "REDIS-DEEP-003",
                    Severity.CRITICAL,
                    "Redis has no password",
                    "A public Redis instance does not require authentication.",
                    "requirepass=<missing>",
                ))
        if self.model.redis_deep.service_state in {"failed", "inactive", "stopped"}:
            if not _docker_redis_running(self.model) and _app_requires_redis(self.model):
                findings.append(_finding(
                    "REDIS-DEEP-007",
                    Severity.CRITICAL,
                    "Redis service is not healthy",
                    f"Redis service state is {self.model.redis_deep.service_state}.",
                    f"service_state={self.model.redis_deep.service_state}",
                ))
        if _app_requires_redis(self.model) and not self.model.redis_deep.scanner_available:
            findings.append(_finding(
                "REDIS-DEEP-008",
                Severity.WARNING,
                "App requires Redis but Redis scanner is unavailable",
                "Application references Redis, but Redis state could not be verified.",
                "redis scanner unavailable",
            ))
        return findings


def is_redis_public(endpoint: NetworkEndpoint) -> bool:
    public = bool(
        getattr(endpoint, "is_public", False)
        or getattr(endpoint, "public_exposed", False)
        or endpoint.address in {"0.0.0.0", "::", "*"}
    )
    return endpoint.port == 6379 and public and endpoint.protocol == "tcp"


def _instance_public(instance: RedisInstance) -> bool:
    return any(addr in {"0.0.0.0", "::", "*"} for addr in instance.bind_addresses)


def _docker_redis_running(model: ServerModel) -> bool:
    if model.nginx is None or model.nginx.mode != "DOCKER":
        return False
    for container in model.services.docker_containers:
        if container.status.startswith("Up") or container.status == "running":
            if "redis" in container.name.lower() or "redis" in container.image.lower():
                return True
    return False


def _app_requires_redis(model: ServerModel) -> bool:
    for project in model.laravel_runtime.projects:
        for key in ("CACHE_DRIVER", "CACHE_STORE", "QUEUE_CONNECTION", "SESSION_DRIVER"):
            if (project.env.get(key) or "").lower() == "redis":
                return True
    return False


def _finding(rule_id, severity, condition, cause, excerpt) -> Finding:
    return Finding(
        id=rule_id,
        severity=severity,
        confidence=0.9,
        condition=condition,
        cause=cause,
        evidence=[Evidence("redis diagnosis", 0, excerpt, "redis/ss scan")],
        treatment="Bind Redis privately, enable protected mode/auth, and verify app dependencies.",
        impact=["Redis data or dependent app features may be exposed or unavailable."],
    )
