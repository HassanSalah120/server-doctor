"""Node, PM2, systemd, and Vite deployment diagnosis."""

from __future__ import annotations

from dataclasses import dataclass
from urllib.parse import urlparse

from server_doctor.model.evidence import Evidence, Severity
from server_doctor.model.finding import Finding
from server_doctor.model.server import NetworkEndpoint, ServerModel


@dataclass
class ProxyTarget:
    host: str
    port: int


class NodeRuntimeAuditor:
    def __init__(self, model: ServerModel) -> None:
        self.model = model

    def audit(self) -> list[Finding]:
        findings: list[Finding] = []
        listeners = _listeners(self.model)
        for server in self.model.nginx.servers if self.model.nginx else []:
            for location in server.locations:
                proxy = location.proxy_pass
                if proxy and proxy_target_not_listening(proxy, listeners):
                    findings.append(Finding(
                        id="NODE-RUNTIME-004",
                        severity=Severity.CRITICAL,
                        confidence=0.9,
                        condition="Nginx proxy target is not listening",
                        cause=f"proxy_pass points to {proxy}, but no local listener matched.",
                        evidence=[
                            Evidence(
                                location.source_file or "nginx config",
                                location.line_number,
                                f"proxy_pass {proxy}",
                                "ss -ltnp",
                            )
                        ],
                        treatment="Start the Node service or update proxy_pass.",
                        impact=["Requests may return 502/503/504."],
                    ))
        for process in self.model.node_runtime.processes:
            if process.status in {"errored", "failed", "crashed"}:
                findings.append(_process_finding(
                    "NODE-RUNTIME-001",
                    Severity.CRITICAL,
                    "Node process manager reports an unstable process",
                    f"{process.name} status is {process.status}.",
                    process,
                ))
            if process.user == "root":
                findings.append(_process_finding(
                    "NODE-RUNTIME-009",
                    Severity.WARNING,
                    "Node process is running as root",
                    "A Node runtime process has root ownership.",
                    process,
                ))
            if process.restart_count is not None and process.restart_count > 10:
                findings.append(_process_finding(
                    "NODE-RUNTIME-010",
                    Severity.WARNING,
                    "Node process restart count is high",
                    f"Restart count is {process.restart_count}.",
                    process,
                ))
        for path in self.model.node_runtime.missing_build_paths:
            findings.append(_path_finding(
                "NODE-RUNTIME-007",
                "Production build folder is missing",
                f"Expected build output is missing at {path}.",
                path,
            ))
        for path in self.model.node_runtime.missing_manifest_paths:
            findings.append(_path_finding(
                "NODE-RUNTIME-008",
                "Vite manifest is missing",
                f"Expected Vite manifest is missing at {path}.",
                path,
            ))
        return findings


def parse_proxy_target(proxy_target: str) -> ProxyTarget | None:
    parsed = urlparse(proxy_target)
    if not parsed.scheme:
        parsed = urlparse("http://" + proxy_target)
    if parsed.port is None:
        return None
    return ProxyTarget(host=parsed.hostname or "", port=parsed.port)


def proxy_target_not_listening(
    proxy_target: str,
    listeners: list[NetworkEndpoint],
) -> bool:
    parsed = parse_proxy_target(proxy_target)
    if parsed is None:
        return False
    if parsed.host not in {"127.0.0.1", "localhost", "0.0.0.0"}:
        return False
    return not any(port.port == parsed.port for port in listeners)


def _listeners(model: ServerModel) -> list[NetworkEndpoint]:
    if model.node_runtime.listeners:
        return model.node_runtime.listeners
    return list(getattr(model.network_surface, "endpoints", []) or [])


def _process_finding(rule_id, severity, condition, cause, process) -> Finding:
    return Finding(
        id=rule_id,
        severity=severity,
        confidence=0.85,
        condition=condition,
        cause=cause,
        evidence=[
            Evidence(
                "process table",
                0,
                f"pid={process.pid} user={process.user} status={process.status}",
                "ps/pm2/systemctl",
            )
        ],
        treatment="Review Node process supervision and runtime user.",
        impact=["Node service reliability or blast radius may be poor."],
    )


def _path_finding(rule_id, condition, cause, path) -> Finding:
    return Finding(
        id=rule_id,
        severity=Severity.WARNING,
        confidence=0.8,
        condition=condition,
        cause=cause,
        evidence=[Evidence(path, 0, "missing", f"test -e {path}")],
        treatment="Build the production assets or update deployment paths.",
        impact=["Frontend assets may fail to load."],
    )
