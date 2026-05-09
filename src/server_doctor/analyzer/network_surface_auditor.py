"""Network Surface Auditor - Detects risky public network exposure."""

from server_doctor.model.evidence import Evidence, Severity
from server_doctor.model.finding import Finding
from server_doctor.model.server import NetworkEndpoint, ServerModel


INSECURE_PUBLIC_PORTS: dict[int, str] = {
    21: "FTP",
    23: "Telnet",
    69: "TFTP",
    110: "POP3",
    143: "IMAP",
}

SENSITIVE_PUBLIC_PORTS: dict[int, str] = {
    2375: "Docker Remote API (unencrypted)",
    3306: "MySQL",
    5432: "PostgreSQL",
    6379: "Redis",
    9200: "Elasticsearch",
    11211: "Memcached",
    27017: "MongoDB",
    3389: "RDP",
}

EXPECTED_PUBLIC_PORTS = {22, 80, 443}


class NetworkSurfaceAuditor:
    """Auditor for network exposure and service fingerprint risks."""

    def __init__(self, model: ServerModel) -> None:
        self.model = model

    def audit(self) -> list[Finding]:
        findings: list[Finding] = []
        if not hasattr(self.model, "network_surface"):
            return findings

        findings.extend(self._check_insecure_public_services())
        findings.extend(self._check_sensitive_public_ports())
        findings.extend(self._check_excess_public_surface())
        findings.extend(self._check_unknown_public_services())
        return findings

    def _public_endpoints(self) -> list[NetworkEndpoint]:
        return [ep for ep in self.model.network_surface.endpoints if ep.public_exposed]

    def _check_insecure_public_services(self) -> list[Finding]:
        risky = [ep for ep in self._public_endpoints() if ep.port in INSECURE_PUBLIC_PORTS]
        if not risky:
            return []

        evidence = [
            Evidence(
                source_file="network-surface",
                line_number=1,
                excerpt=f"{ep.protocol.upper()} {ep.address}:{ep.port} ({ep.program or ep.service or 'unknown'})",
                command="ss -H -lntuap",
            )
            for ep in risky[:8]
        ]
        return [
            Finding(
                id="NET-1",
                severity=Severity.CRITICAL,
                confidence=0.95,
                condition=f"{len(risky)} insecure cleartext service(s) exposed publicly",
                cause="Legacy protocols without strong transport security are listening on public interfaces.",
                evidence=evidence,
                treatment="Disable these listeners or place them behind VPN/private network with secure alternatives.",
                impact=[
                    "Credential interception and session hijacking risk",
                    "Larger attack surface for brute-force/exploit traffic",
                ],
            )
        ]

    def _check_sensitive_public_ports(self) -> list[Finding]:
        risky = [ep for ep in self._public_endpoints() if ep.port in SENSITIVE_PUBLIC_PORTS]
        if not risky:
            return []

        severity = Severity.CRITICAL if self.model.services.firewall != "present" else Severity.WARNING
        evidence = [
            Evidence(
                source_file="network-surface",
                line_number=1,
                excerpt=f"{ep.address}:{ep.port} {SENSITIVE_PUBLIC_PORTS.get(ep.port, ep.service or '')}",
                command="ss -H -lntuap",
            )
            for ep in risky[:8]
        ]
        return [
            Finding(
                id="NET-2",
                severity=severity,
                confidence=0.92,
                condition=f"{len(risky)} sensitive service port(s) exposed publicly",
                cause="Database/control-plane services are listening on 0.0.0.0/::.",
                evidence=evidence,
                treatment="Bind sensitive services to localhost/private interfaces and enforce network ACL/firewall rules.",
                impact=[
                    "High-value services are directly reachable from untrusted networks",
                    "Data exfiltration and unauthorized control risk",
                ],
            )
        ]

    def _check_excess_public_surface(self) -> list[Finding]:
        public_ports = sorted({ep.port for ep in self._public_endpoints()})
        nonstandard = [p for p in public_ports if p not in EXPECTED_PUBLIC_PORTS]
        if len(nonstandard) <= 3:
            return []

        severity = Severity.CRITICAL if len(nonstandard) >= 8 else Severity.WARNING
        return [
            Finding(
                id="NET-3",
                severity=severity,
                confidence=0.85,
                condition=f"Large public attack surface detected ({len(nonstandard)} non-standard public ports)",
                cause="Many ports beyond 22/80/443 are exposed on public interfaces.",
                evidence=[
                    Evidence(
                        source_file="network-surface",
                        line_number=1,
                        excerpt=", ".join(str(p) for p in nonstandard[:12]),
                        command="ss -H -lntuap",
                    )
                ],
                treatment="Close unused public ports and enforce least-privilege inbound exposure.",
                impact=[
                    "Attack surface increases with every exposed service",
                    "Operational/security monitoring burden rises",
                ],
            )
        ]

    def _check_unknown_public_services(self) -> list[Finding]:
        unknown = [
            ep
            for ep in self._public_endpoints()
            if ep.port not in EXPECTED_PUBLIC_PORTS and (not ep.service or ep.service == "unknown")
        ]
        if not unknown:
            return []

        evidence = [
            Evidence(
                source_file="network-surface",
                line_number=1,
                excerpt=f"{ep.protocol.upper()} {ep.address}:{ep.port} program={ep.program or 'unknown'}",
                command="ss -H -lntuap",
            )
            for ep in unknown[:8]
        ]
        return [
            Finding(
                id="NET-4",
                severity=Severity.INFO,
                confidence=0.70,
                condition=f"{len(unknown)} public service endpoint(s) could not be confidently fingerprinted",
                cause="Program/service identity is ambiguous for exposed endpoints.",
                evidence=evidence,
                treatment="Verify owner process and intended exposure for these ports.",
                impact=[
                    "Untracked services may bypass standard hardening and monitoring",
                ],
            )
        ]
