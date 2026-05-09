"""Node/Vite/Inertia deployment checks."""

from __future__ import annotations

import re
from typing import Any

from server_doctor.checks import BaseCheck, CheckContext, register_check
from server_doctor.model.evidence import Evidence, Severity
from server_doctor.model.finding import Finding

VITE_MANIFEST_PATHS = [
    "public/build/manifest.json",
    "public/assets/manifest.json",
]
CORS_WILDCARD_RE = re.compile(r"Access-Control-Allow-Origin\s*[:=]\s*['\"]?\*", re.I)
CORS_CREDENTIALS_RE = re.compile(
    r"Access-Control-Allow-Credentials\s*[:=]\s*['\"]?true",
    re.I,
)


@register_check
class NodeDeployAuditor(BaseCheck):
    @property
    def category(self) -> str:
        return "node"

    @property
    def requires_ssh(self) -> bool:
        return False

    def run(self, context: CheckContext) -> list[Finding]:
        findings: list[Finding] = []
        for process in self._node_processes(context.model):
            owner = getattr(process, "user", None) or getattr(process, "owner", None)
            if owner is None:
                continue
            if str(owner).strip() == "root":
                pid = getattr(process, "pid", "unknown")
                findings.append(
                    Finding(
                        id="NODE-DEPLOY-003",
                        severity=Severity.WARNING,
                        confidence=0.9,
                        condition="Node process is running as root",
                        cause="A Node runtime process has root ownership.",
                        evidence=[
                            Evidence(
                                source_file="process table",
                                line_number=0,
                                excerpt=f"pid={pid} user=root",
                                command="ps/ss node process inventory",
                            )
                        ],
                        treatment=(
                            "Run the Node service as a dedicated unprivileged "
                            "application user."
                        ),
                        impact=["A process compromise may become a root-level compromise."],
                    )
                )
        return findings

    @staticmethod
    def _node_processes(model: Any) -> list[Any]:
        services = getattr(model, "services", None)
        return list(getattr(services, "node_processes", []) or [])
