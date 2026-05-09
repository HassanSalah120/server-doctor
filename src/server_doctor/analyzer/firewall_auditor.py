"""Firewall Auditor - Flags missing local firewall controls."""

from server_doctor.model.evidence import Evidence, Severity
from server_doctor.model.finding import Finding
from server_doctor.model.server import ServerModel


class FirewallAuditor:
    """Auditor for local firewall posture."""

    def __init__(self, model: ServerModel) -> None:
        self.model = model

    def audit(self) -> list[Finding]:
        """Run firewall checks."""
        findings: list[Finding] = []

        if not hasattr(self.model, "services"):
            return findings

        firewall_state = self.model.services.firewall
        has_public_services = self._has_public_services()

        if firewall_state == "not_detected" and has_public_services:
            findings.append(
                Finding(
                    id="FIREWALL-1",
                    severity=Severity.WARNING,
                    confidence=0.85,
                    condition="No local firewall rules detected on a publicly served host",
                    cause="No active ufw/nftables/iptables rule set was detected.",
                    evidence=[
                        Evidence(
                            source_file="host-firewall",
                            line_number=1,
                            excerpt="ufw/nft/iptables rules not detected",
                            command="ufw status || nft list ruleset || iptables -S",
                        )
                    ],
                    treatment=(
                        "Enable host firewall with least-privilege inbound rules "
                        "(typically 22, 80, 443 only as needed)."
                    ),
                    impact=[
                        "Unnecessary exposed ports may be reachable from the network",
                        "Higher blast radius if any service is misconfigured",
                    ],
                )
            )

        if firewall_state == "unknown" and has_public_services:
            findings.append(
                Finding(
                    id="FIREWALL-2",
                    severity=Severity.INFO,
                    confidence=0.60,
                    condition="Firewall status could not be verified",
                    cause="Could not determine local firewall state from available tooling.",
                    evidence=[
                        Evidence(
                            source_file="host-firewall",
                            line_number=1,
                            excerpt="firewall status unknown",
                            command="which ufw; which nft; which iptables",
                        )
                    ],
                    treatment="Verify host/network firewall policy manually for exposed services.",
                    impact=[
                        "Security posture may be weaker than expected",
                    ],
                )
            )

        findings.extend(self._check_firewall_public_exposure_correlation(firewall_state))
        return findings

    def _check_firewall_public_exposure_correlation(self, firewall_state: str) -> list[Finding]:
        if firewall_state != "present":
            return []
        endpoints = getattr(getattr(self.model, "network_surface", None), "endpoints", []) or []
        public_ports = sorted({ep.port for ep in endpoints if getattr(ep, "public_exposed", False)})
        noisy = [p for p in public_ports if p not in {22, 80, 443}]
        if len(noisy) <= 3:
            return []
        return [
            Finding(
                id="FIREWALL-3",
                severity=Severity.INFO,
                confidence=0.78,
                condition=f"Firewall is present but {len(noisy)} non-standard public port(s) remain reachable",
                cause="Host firewall policy does not appear to restrict exposed application ports to a minimal ingress set.",
                evidence=[
                    Evidence(
                        source_file="host-firewall",
                        line_number=1,
                        excerpt=f"Public ports observed: {', '.join(str(p) for p in noisy[:12])}",
                        command="ufw status / ss -tulpn correlation",
                    )
                ],
                treatment="Review ufw allow rules and close non-essential public ports.",
                impact=[
                    "Firewall posture may not match intended least-privilege network policy",
                ],
            )
        ]

    def _has_public_services(self) -> bool:
        # Nginx servers with standard public listen ports.
        if self.model.nginx:
            for server in self.model.nginx.servers:
                for listen in server.listen:
                    if any(p in listen for p in ("80", "443")):
                        return True

        # Public MySQL bind is also a public service surface.
        if any(a in ("0.0.0.0", "::", "*") for a in self.model.services.mysql_bind_addresses):
            return True

        # Docker published ports on all interfaces.
        for container in self.model.services.docker_containers:
            for port in container.ports:
                if port.host_port and port.host_ip in ("0.0.0.0", "::"):
                    return True

        return False
