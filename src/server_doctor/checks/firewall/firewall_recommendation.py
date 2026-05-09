"""Firewall recommendation checks."""

from __future__ import annotations

from pydantic import BaseModel

from server_doctor.checks import BaseCheck, CheckContext, register_check
from server_doctor.model.evidence import Evidence, Severity
from server_doctor.model.finding import Finding

MYSQL_PORTS = {3306}
REDIS_PORTS = {6379}


class FirewallRecommendation(BaseModel):
    title: str
    risk: str
    commands: list[str]
    rollback_commands: list[str]


def recommend_mysql_lockdown(port: int = 3306) -> FirewallRecommendation:
    return FirewallRecommendation(
        title="Restrict public MySQL access",
        risk="high",
        commands=[f"sudo ufw deny {port}/tcp"],
        rollback_commands=[f"sudo ufw delete deny {port}/tcp"],
    )


@register_check
class FirewallRecommendationAuditor(BaseCheck):
    @property
    def category(self) -> str:
        return "firewall"

    @property
    def requires_ssh(self) -> bool:
        return False

    def run(self, context: CheckContext) -> list[Finding]:
        findings: list[Finding] = []
        network = getattr(context.model, "network_surface", None)
        endpoints = (
            getattr(network, "endpoints", None)
            or getattr(network, "listeners", [])
            or []
        )
        for endpoint in endpoints:
            port = getattr(endpoint, "port", None)
            protocol = str(getattr(endpoint, "protocol", "tcp")).lower()
            public = bool(
                getattr(endpoint, "is_public", False)
                or getattr(endpoint, "public_exposed", False)
            )
            if not public or protocol != "tcp":
                continue
            if port in REDIS_PORTS:
                findings.append(
                    Finding(
                        id="FW-REC-003",
                        severity=Severity.CRITICAL,
                        confidence=0.9,
                        condition="Redis port is publicly reachable",
                        cause=(
                            "A Redis endpoint is listening on a public TCP interface."
                        ),
                        evidence=[
                            Evidence(
                                "network surface",
                                0,
                                f"tcp/{port} public",
                                "network surface scan",
                            )
                        ],
                        treatment=(
                            "Restrict Redis to localhost/private networks and deny "
                            "public firewall access."
                        ),
                        impact=[
                            "Unauthenticated or weakly protected Redis can expose or "
                            "alter application data."
                        ],
                    )
                )
            if port in MYSQL_PORTS:
                findings.append(
                    Finding(
                        id="FW-REC-002",
                        severity=Severity.CRITICAL,
                        confidence=0.9,
                        condition="Database port is publicly reachable",
                        cause=(
                            "A database endpoint is listening on a public TCP interface."
                        ),
                        evidence=[
                            Evidence(
                                "network surface",
                                0,
                                f"tcp/{port} public",
                                "network surface scan",
                            )
                        ],
                        treatment=(
                            "Restrict the database port with firewall rules or private "
                            "binding."
                        ),
                        impact=["Database access may be exposed beyond trusted hosts."],
                    )
                )
        return findings
