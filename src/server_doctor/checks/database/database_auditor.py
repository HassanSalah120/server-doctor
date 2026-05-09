"""Database exposure checks."""

from __future__ import annotations

import re

from server_doctor.checks import BaseCheck, CheckContext, register_check
from server_doctor.model.evidence import Evidence, Severity
from server_doctor.model.finding import Finding

PRIVATE_BIND_ADDRESSES = {"127.0.0.1", "::1", "localhost"}
PUBLIC_BIND_RE = re.compile(r"^(0\.0\.0\.0|::|\*)$")


@register_check
class DatabaseAuditor(BaseCheck):
    @property
    def category(self) -> str:
        return "database"

    @property
    def requires_ssh(self) -> bool:
        return False

    def run(self, context: CheckContext) -> list[Finding]:
        findings: list[Finding] = []
        services = getattr(context.model, "services", None)
        for address in getattr(services, "mysql_bind_addresses", []) or []:
            if PUBLIC_BIND_RE.match(str(address)):
                findings.append(
                    Finding(
                        id="DB-001",
                        severity=Severity.CRITICAL,
                        confidence=0.9,
                        condition="MySQL bind address is public",
                        cause="MySQL is configured to bind on a public interface.",
                        evidence=[
                            Evidence(
                                "mysql config",
                                0,
                                f"bind-address={address}",
                                "mysql config scan",
                            )
                        ],
                        treatment=(
                            "Bind MySQL to 127.0.0.1 or a private interface."
                        ),
                        impact=["Database service may be reachable from the internet."],
                    )
                )
        return findings
