"""Finding Correlation Engine - Synthesizes isolated findings into root-cause insights.

Detects patterns across multiple findings (same component, server block, or domain)
to emit a single "Synthesized Finding" (Correlation) with root-cause and blast radius.
"""

from dataclasses import dataclass, field
from typing import Any, Protocol

from server_doctor.model.finding import Finding
from server_doctor.model.server import ServerModel


@dataclass
class SynthesizedFinding:
    """A higher-level finding produced by correlating multiple raw findings."""
    correlation_id: str
    root_cause_hypothesis: str
    blast_radius: str
    severity: str
    supporting_rule_ids: list[str] = field(default_factory=list)
    fix_bundle: list[dict[str, Any]] = field(default_factory=list)
    confidence: float = 0.0


class CorrelationEngine:
    """Engine that analyzes findings and topology to find correlations."""

    def __init__(self, findings: list[Finding], topology: ServerModel) -> None:
        self.findings = findings
        self.topology = topology
        self.rules: list[str] = [f.id for f in findings]

    def correlate(self) -> list[SynthesizedFinding]:
        """Run all correlation rules and return synthesized findings."""
        results: list[SynthesizedFinding] = []
        
        # 1. Header inheritance broken (add_header override)
        header_cor = self._check_header_inheritance()
        if header_cor:
            results.append(header_cor)
            
        # 2. Unintended exposure (Open port + firewall - Nginx)
        exposure_cor = self._check_unintended_exposure()
        if exposure_cor:
            results.append(exposure_cor)
            
        # 3. TLS Posture (Docker ingress + missing hardening)
        tls_cor = self._check_tls_posture()
        if tls_cor:
            results.append(tls_cor)

        # 4. Misrouted traffic (Duplicate server_name, etc.)
        routing_cor = self._check_routing_conflicts()
        if routing_cor:
            results.append(routing_cor)

        # 5. Compromise chain: admin + debug + env/file exposure + weak firewall
        compromise_cor = self._check_compromise_chain()
        if compromise_cor:
            results.append(compromise_cor)

        return results

    def _check_header_inheritance(self) -> SynthesizedFinding | None:
        """Pattern: Many locations missing security headers."""
        header_rules = {"SEC-HEAD-1"}
        relevant = [f for f in self.findings if f.id in header_rules]
        
        if len(relevant) >= 5:  # Arbitrary threshold for "many"
            # Calculate blast radius
            domains = set()
            for f in relevant:
                if f.evidence and "server_name" in f.evidence:
                    domains.add(f.evidence.get("server_name"))
            
            domain_str = f"Over {len(domains)} domains" if domains else "Multiple locations"
            
            return SynthesizedFinding(
                correlation_id="header-inheritance-broken",
                root_cause_hypothesis="Security headers are being overridden by local 'add_header' directives or missing at the 'http' block level, breaking inheritance.",
                blast_radius=f"Impacts security posture across {domain_str}.",
                severity="medium",
                supporting_rule_ids=list(set(f.id for f in relevant)),
                confidence=0.9,
                fix_bundle=[
                    {
                        "step": "Consolidate security headers into a shared 'security_headers.conf' and include it in the 'http' block.",
                        "effort": "low"
                    },
                    {
                        "step": "Use 'add_header ... always;' to ensure headers are sent even on error pages.",
                        "effort": "low"
                    }
                ]
            )
        return None

    def _check_unintended_exposure(self) -> SynthesizedFinding | None:
        """Pattern: Open port + Firewall allows + Not in Nginx."""
        # Check network surface for exposed endpoints
        exposed_endpoints = []
        if self.topology.network_surface:
            exposed_endpoints = [e for e in self.topology.network_surface.endpoints if e.public_exposed]
            
        nginx_ports = set()
        if self.topology.nginx:
            for s in self.topology.nginx.servers:
                # listen can be "80", "443 ssl", etc.
                for l in s.listen:
                    try:
                        port = int(l.split()[0])
                        nginx_ports.add(port)
                    except (ValueError, IndexError):
                        continue

        rogue_ports = [e for e in exposed_endpoints if e.port not in nginx_ports and e.port not in (22, 80, 443)]
        
        if rogue_ports:
            port_list = ", ".join(str(e.port) for e in rogue_ports)
            return SynthesizedFinding(
                correlation_id="unintended-exposure-risk",
                root_cause_hypothesis=f"Services are listening on public ports ({port_list}) that are not proxied by Nginx and are allowed by the firewall.",
                blast_radius=f"Direct exposure of internal services on ports: {port_list}.",
                severity="high",
                supporting_rule_ids=["NGX-SEC-2", "NGX-SEC-3"],
                confidence=0.85,
                fix_bundle=[
                    {
                        "step": f"Close ports {port_list} in the firewall if direct access is not required.",
                        "effort": "medium"
                    },
                    {
                        "step": "Configure services to listen on 127.0.0.1 and proxy them via Nginx.",
                        "effort": "medium"
                    }
                ]
            )
        return None

    def _check_tls_posture(self) -> SynthesizedFinding | None:
        """Pattern: Docker ingress + missing TLS hardening."""
        is_docker = "docker" in self.topology.hostname or (hasattr(self.topology, "services") and self.topology.services.docker_containers)
        
        missing_tls_hardening = any(f.id == "SEC-TLS-1" for f in self.findings)
        missing_ssl_certs = any(f.id == "SEC-TLS-2" for f in self.findings)
        
        if is_docker and (missing_tls_hardening or missing_ssl_certs):
            return SynthesizedFinding(
                correlation_id="ingress-tls-posture-risk",
                root_cause_hypothesis="Containerized ingress is configured without modern TLS hardening (hsts, ciphers, or valid certs).",
                blast_radius="Exposure of all containerized web traffic to man-in-the-middle or downgrade attacks.",
                severity="high",
                supporting_rule_ids=["SEC-TLS-1", "SEC-TLS-2"],
                confidence=0.8,
                fix_bundle=[
                    {
                        "step": "Implement a centralized TLS termination strategy (e.g. Nginx Proxy Manager or Traefik).",
                        "effort": "high"
                    },
                    {
                        "step": "Enforce TLS 1.2+ and modern cipher suites in Nginx global config.",
                        "effort": "low"
                    }
                ]
            )
        return None

    def _check_routing_conflicts(self) -> SynthesizedFinding | None:
        """Pattern: Duplicate server_name or overlapping locations."""
        duplicate_server = any(f.id == "NGX-SEC-5" for f in self.findings)
        regex_conflict = any(f.id == "NGX-SEC-6" for f in self.findings)
        
        if duplicate_server or regex_conflict:
            return SynthesizedFinding(
                correlation_id="misrouted-traffic-risk",
                root_cause_hypothesis="Overlapping 'server_name' directives or ambiguous 'location' blocks are causing Nginx to route traffic to incorrect backends.",
                blast_radius="Potential disclosure of internal routes or broken application functionality for specific domains.",
                severity="medium",
                supporting_rule_ids=["NGX-SEC-5", "NGX-SEC-6"],
                confidence=0.9,
                fix_bundle=[
                    {
                        "step": "Audit 'server_name' directives for exact duplicates.",
                        "effort": "medium"
                    },
                    {
                        "step": "Use the '^~' prefix for static location blocks to avoid regex interference.",
                        "effort": "low"
                    }
                ]
            )
        return None

    def _check_compromise_chain(self) -> SynthesizedFinding | None:
        """Pattern: exposed admin/dashboard + debug flag + .env leakage + weak/no firewall."""
        present = {f.id for f in self.findings}
        # require sensitive path plus either laravel debug or dotfile exposure and firewall warning
        if "NGX-SENS-1" in present and (
            ("LARAVEL-1" in present or "NGX-SEC-3" in present) and "FIREWALL-1" in present
        ):
            return SynthesizedFinding(
                correlation_id="full-compromise-chain",
                root_cause_hypothesis=(
                    "Public admin/debug interface reachable for an application with debug enabled "
                    "and exposed .env or missing dotfile protection while the host firewall is absent."
                ),
                blast_radius="Potential full application and host compromise",
                severity="critical",
                supporting_rule_ids=list(present & {"NGX-SENS-1", "LARAVEL-1", "NGX-SEC-3", "FIREWALL-1"}),
                confidence=0.85,
                fix_bundle=[
                    {"step": "Close admin/debug paths or require authentication.", "effort": "medium"},
                    {"step": "Disable APP_DEBUG and protect .env files.", "effort": "low"},
                    {"step": "Enable and tighten local firewall rules.", "effort": "low"},
                ],
            )
        return None
