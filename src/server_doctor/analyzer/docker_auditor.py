"""Docker Auditor - Identifies misconfigurations in containerized environments.
"""

from server_doctor.model.evidence import Evidence, Severity
from server_doctor.model.finding import Finding
from server_doctor.model.server import CapabilityLevel, ServerModel
import re


class DockerAuditor:
    """Auditor for Docker-specific diagnostic checks."""

    def __init__(self, model: ServerModel) -> None:
        self.model = model

    def audit(self) -> list[Finding]:
        """Run all Docker diagnostic checks."""
        findings: list[Finding] = []
        if self.model.services.docker.capability == CapabilityLevel.NONE:
            return findings

        findings.extend(self._check_container_restarts())
        findings.extend(self._check_direct_exposure())
        findings.extend(self._check_socket_permissions())
        return findings

    def _check_container_restarts(self) -> list[Finding]:
        """Check for containers in restart loops (DOCKER-1)."""
        findings: list[Finding] = []
        for container in self.model.services.docker_containers:
            if container.restart_count >= 5:
                severity = Severity.CRITICAL if container.restart_count >= 20 else Severity.WARNING
                findings.append(Finding(
                    severity=severity,
                    confidence=1.0,
                    condition=f"Docker container '{container.name}' is restarting frequently",
                    cause=f"Restart count is {container.restart_count}",
                    evidence=[Evidence(
                        source_file="docker",
                        line_number=1,
                        excerpt=f"Container: {container.name}, Image: {container.image}, Restarts: {container.restart_count}",
                        command="docker inspect"
                    )],
                    treatment="Check container logs using 'docker logs " + container.name + "' to identify the crash cause.",
                    impact=["Service instability", "Potential data corruption", "Resource exhaustion"],
                    correlation=self._get_correlations(container.name)
                ))
        return findings

    def _check_direct_exposure(self) -> list[Finding]:
        """Check for published ports not proxied by Nginx (DOCKER-2 / SHADOW-1)."""
        findings: list[Finding] = []

        covered_host_ports = self._get_nginx_proxied_ports()
        dev_ports = {3000, 3001, 4173, 5173, 8080, 8081}
        firewall_missing = (self.model.services.firewall or "").lower() == "not_detected"
        ingress_containers = self._detect_ingress_containers()
        ingress_count = len(ingress_containers)

        # 2. Check each container's published ports
        for container in self.model.services.docker_containers:
            for port in container.ports:
                is_public = port.host_ip == "0.0.0.0" or port.host_ip == "::"
                is_ingress_container = container.name in ingress_containers
                if port.host_port in {80, 443} and is_public and is_ingress_container:
                    if port.host_port == 443 and ingress_count > 1:
                        findings.append(Finding(
                            id="DOCKER-4",
                            severity=Severity.WARNING,
                            confidence=0.88,
                            condition="Multiple ingress containers publish HTTPS (443)",
                            cause="More than one ingress-like container publishes 443 publicly.",
                            evidence=[Evidence(
                                source_file="docker",
                                line_number=1,
                                excerpt=f"Container '{container.name}' publishes {port.host_ip}:{port.host_port}",
                                command="docker ps"
                            )],
                            treatment="Keep one authoritative ingress for 443 or isolate secondary ingress bindings.",
                            impact=["TLS ingress ambiguity", "Inconsistent routing/certificate behavior"],
                        ))
                    # Expected ingress exposure on 80/443 is topology metadata, not a finding.
                    continue

                if port.host_port and port.host_port not in covered_host_ports:
                    if is_public:
                        is_dev_port = port.host_port in dev_ports
                        is_non_ingress_443 = port.host_port == 443 and not is_ingress_container
                        severity = Severity.CRITICAL if (is_dev_port or firewall_missing) else Severity.WARNING
                        firewall_posture, firewall_note = self._classify_firewall_posture(port.host_port, port.proto)
                        if firewall_posture == "BLOCKED":
                            severity, latent_note = self._downgrade_blocked_severity(severity)
                        else:
                            latent_note = ""
                        if is_dev_port:
                            risk_hint = "Public dev/server port exposure is high-risk in production."
                        elif is_non_ingress_443:
                            risk_hint = "Non-ingress service is publishing 443 directly."
                        elif firewall_missing:
                            risk_hint = "Port is publicly reachable, unproxied, and host firewall appears missing."
                        else:
                            risk_hint = "Container port is directly reachable from public network."
                        findings.append(Finding(
                            severity=severity,
                            confidence=0.9,
                            condition=f"Docker port {port.host_port} is exposed publicly bypassing Nginx",
                            cause=(
                                f"Container '{container.name}' publishes port {port.host_port} on {port.host_ip} "
                                f"but no Nginx proxy_pass covers it. {risk_hint} "
                                f"{firewall_note}. {latent_note}".strip()
                            ),
                            evidence=[Evidence(
                                source_file="docker",
                                line_number=1,
                                excerpt=f"Port Binding: {port.host_ip}:{port.host_port} -> {port.container_port}/{port.proto}",
                                command="docker ps"
                            )],
                            treatment=f"Bind to 127.0.0.1 instead: -p 127.0.0.1:{port.host_port}:{port.container_port}. Or secure via firewall.",
                            impact=["Bypasses Nginx authentication/rate-limits", "Direct attack surface exposure", "Potential for 'Shadow Routing'"]
                        ))
                elif port.host_port and port.host_port in covered_host_ports:
                    if is_public:
                        is_intended_ingress = port.host_port in {80, 443} and is_ingress_container
                        if port.host_port == 443 and ingress_count > 1 and is_ingress_container:
                            findings.append(Finding(
                                id="DOCKER-4",
                                severity=Severity.WARNING,
                                confidence=0.88,
                                condition="Multiple ingress containers publish HTTPS (443)",
                                cause=(
                                    "More than one ingress-like container publishes 443 publicly, which can create "
                                    "ambiguous TLS entrypoints."
                                ),
                                evidence=[Evidence(
                                    source_file="docker",
                                    line_number=1,
                                    excerpt=f"Container '{container.name}' publishes {port.host_ip}:{port.host_port}",
                                    command="docker ps"
                                )],
                                treatment="Keep one authoritative ingress for 443 or isolate secondary ingress bindings.",
                                impact=["TLS ingress ambiguity", "Inconsistent routing/certificate behavior"],
                            ))
                            continue
                        if port.host_port == 443 and not is_ingress_container:
                            firewall_posture, firewall_note = self._classify_firewall_posture(port.host_port, port.proto)
                            severity = Severity.WARNING
                            latent_note = ""
                            if firewall_posture == "BLOCKED":
                                severity, latent_note = self._downgrade_blocked_severity(severity)
                            findings.append(Finding(
                                id="DOCKER-5",
                                severity=severity,
                                confidence=0.9,
                                condition=f"Non-ingress container '{container.name}' exposes HTTPS port 443 publicly",
                                cause=(
                                    "Port 443 should usually be reserved for the reverse proxy ingress path. "
                                    f"{firewall_note}. {latent_note}".strip()
                                ),
                                evidence=[Evidence(
                                    source_file="docker",
                                    line_number=1,
                                    excerpt=f"Port Binding: {port.host_ip}:{port.host_port} -> {port.container_port}/{port.proto}",
                                    command="docker ps"
                                )],
                                treatment="Move this service behind ingress or rebind 443 to localhost/internal network only.",
                                impact=["Potential TLS bypass and policy drift", "Confusing external ingress topology"],
                            ))
                            continue
                        firewall_posture, firewall_note = self._classify_firewall_posture(port.host_port, port.proto)
                        base_severity = Severity.INFO if is_intended_ingress else Severity.WARNING
                        if is_intended_ingress:
                            # Expected primary ingress exposure; avoid noisy informational finding.
                            continue
                        severity = base_severity
                        latent_note = ""
                        if firewall_posture == "BLOCKED":
                            severity, latent_note = self._downgrade_blocked_severity(base_severity)
                        findings.append(Finding(
                            id="DOCKER-3",
                            severity=severity,
                            confidence=0.80,
                            condition=f"Docker port {port.host_port} is public and also routed through Nginx",
                            cause=(
                                f"Container '{container.name}' publishes {port.host_port} publicly while Nginx already proxies "
                                f"the same backend port. {firewall_note}. {latent_note}".strip()
                            ),
                            evidence=[Evidence(
                                source_file="docker",
                                line_number=1,
                                excerpt=f"Port Binding: {port.host_ip}:{port.host_port} -> {port.container_port}/{port.proto}",
                                command="docker ps"
                            )],
                            treatment=(
                                "If direct access is not required, bind this port to localhost "
                                "or remove public port mapping to enforce Nginx-only ingress."
                            ),
                            impact=[
                                "Potential policy bypass if direct endpoint behavior differs from proxied path."
                            ] if not is_intended_ingress else [
                                "Usually acceptable for primary ingress, but keep only necessary exposed ports."
                            ],
                        ))
                    
        return findings

    def _downgrade_blocked_severity(self, severity: Severity) -> tuple[Severity, str]:
        if severity == Severity.CRITICAL:
            return (Severity.WARNING, "Blocked today but published: latent risk if firewall changes.")
        if severity == Severity.WARNING:
            return (Severity.INFO, "Blocked today but published: latent risk if firewall changes.")
        return (severity, "Blocked today but published.")

    def _classify_firewall_posture(self, port: int, proto: str) -> tuple[str, str]:
        ufw_enabled = getattr(self.model.services, "firewall_ufw_enabled", None)
        default_incoming = (getattr(self.model.services, "firewall_ufw_default_incoming", None) or "").lower()
        rules = [str(r).lower() for r in (getattr(self.model.services, "firewall_rules", []) or [])]
        proto = (proto or "tcp").lower()
        if ufw_enabled is None:
            return ("UNKNOWN", "Firewall posture unknown")
        if ufw_enabled is False:
            return ("OPEN", "UFW inactive")
        allow = False
        deny = False
        token = f"{port}/{proto}"
        bare = f"{port}"
        for rule in rules:
            if token in rule or re.search(rf"\b{bare}\b", rule):
                if "allow" in rule:
                    allow = True
                if "deny" in rule or "reject" in rule:
                    deny = True
        if allow and not deny:
            return ("OPEN", "Explicit UFW allow rule")
        if deny and not allow:
            return ("BLOCKED", "Explicit UFW deny/reject rule")
        if default_incoming in {"deny", "reject"}:
            return ("BLOCKED", "UFW default incoming deny")
        if default_incoming == "allow":
            return ("OPEN", "UFW default incoming allow")
        return ("UNKNOWN", "No matching UFW rule")

    def _detect_ingress_containers(self) -> set[str]:
        names: set[str] = set()
        ingress_keywords = ("nginx", "reverse-proxy", "proxy", "traefik", "caddy", "haproxy")
        for container in self.model.services.docker_containers:
            name = (container.name or "").lower()
            image = (container.image or "").lower()
            publishes_ingress = any(
                p.host_port in {80, 443} and p.host_ip in {"0.0.0.0", "::"}
                for p in (container.ports or [])
                if p.host_port is not None
            )
            ingress_named = any(k in name or k in image for k in ingress_keywords)
            if publishes_ingress and ingress_named:
                names.add(container.name)
        return names

    def _get_nginx_proxied_ports(self) -> set[int]:
        """Extract backend TCP ports referenced by proxy_pass/upstream directives."""
        ports: set[int] = set()
        if not self.model.nginx:
            return ports

        upstream_ports: dict[str, set[int]] = {}
        for upstream in self.model.nginx.upstreams:
            bucket: set[int] = set()
            for target in upstream.servers:
                parsed = self._extract_port_from_target(target)
                if parsed is not None:
                    bucket.add(parsed)
            upstream_ports[upstream.name] = bucket

        for server in self.model.nginx.servers:
            for location in server.locations:
                proxy_pass = (location.proxy_pass or "").strip()
                if not proxy_pass:
                    continue

                direct = self._extract_port_from_target(proxy_pass)
                if direct is not None:
                    ports.add(direct)
                    continue

                upstream_name = self._extract_upstream_name(proxy_pass)
                if upstream_name and upstream_name in upstream_ports:
                    ports.update(upstream_ports[upstream_name])

        return ports

    def _extract_port_from_target(self, target: str) -> int | None:
        # Handles "http://127.0.0.1:3000", "127.0.0.1:3000", "[::1]:3000"
        cleaned = target.strip().rstrip(";")
        for prefix in ("http://", "https://"):
            if cleaned.startswith(prefix):
                cleaned = cleaned[len(prefix):]
        if cleaned.startswith("unix:"):
            return None
        if "/" in cleaned:
            cleaned = cleaned.split("/", 1)[0]
        if cleaned.startswith("[") and "]:" in cleaned:
            cleaned = cleaned.rsplit("]:", 1)[1]
        elif ":" in cleaned:
            cleaned = cleaned.rsplit(":", 1)[1]
        if cleaned.isdigit():
            return int(cleaned)
        return None

    def _extract_upstream_name(self, proxy_pass: str) -> str | None:
        cleaned = proxy_pass.strip().rstrip(";")
        for prefix in ("http://", "https://"):
            if cleaned.startswith(prefix):
                cleaned = cleaned[len(prefix):]
        if "/" in cleaned:
            cleaned = cleaned.split("/", 1)[0]
        if ":" in cleaned or cleaned.startswith("["):
            return None
        return cleaned if cleaned else None

    def _check_socket_permissions(self) -> list[Finding]:
        """Check for docker.sock permission risks (DOCKER-RISK-1)."""
        findings: list[Finding] = []
        # This would require more stat info, but we can flag if we had permission issues earlier
        if self.model.services.docker.reason == "permission_denied":
            findings.append(Finding(
                severity=Severity.INFO,
                confidence=1.0,
                condition="Server Doctor has limited Docker visibility",
                cause="Access to /var/run/docker.sock was denied (Permission Denied)",
                evidence=[Evidence(
                    source_file="/var/run/docker.sock",
                    line_number=1,
                    excerpt="Permission Denied",
                    command="stat /var/run/docker.sock"
                )],
                treatment="Run Server Doctor as a user in the 'docker' group or use sudo.",
                impact=["Incomplete audit", "Missed containerized service correlations"]
            ))
        return findings

    def _get_correlations(self, entity_name: str) -> list:
        """Helper to find correlations for a container/process."""
        correlations = []
        if not hasattr(self.model, "projects"):
            return correlations
        for project in self.model.projects:
            for ev in project.correlation:
                if entity_name in ev.matched_entity:
                    correlations.append(ev)
        return correlations
