"""Node.js Auditor - Identifies misconfigurations in Node.js deployments.
"""

import re
from server_doctor.model.evidence import Evidence, Severity
from server_doctor.model.finding import Finding
from server_doctor.model.server import ServerModel


class NodeAuditor:
    """Auditor for Node.js-specific diagnostic checks."""

    def __init__(self, model: ServerModel) -> None:
        self.model = model

    def audit(self) -> list[Finding]:
        """Run all Node.js diagnostic checks."""
        findings: list[Finding] = []
        if self.model.services.node.capability == "none":
            return findings

        findings.extend(self._check_dev_servers())
        findings.extend(self._check_environment_sources())
        return findings

    def _check_dev_servers(self) -> list[Finding]:
        """Check for development servers running in production (NODE-1)."""
        findings: list[Finding] = []
        dev_patterns = ["npm run dev", "vite", "next dev", "nodemon", "ts-node-dev"]
        
        for proc in self.model.services.node_processes:
            if any(p in proc.cmdline for p in dev_patterns):
                findings.append(Finding(
                    severity=Severity.CRITICAL,
                    confidence=0.9,
                    condition="Node.js development server detected in production",
                    cause=f"Process {proc.pid} is running: {proc.cmdline}",
                    evidence=[Evidence(
                        source_file="ps",
                        line_number=1,
                        excerpt=proc.cmdline,
                        command="ps aux"
                    )],
                    treatment="Use production-ready methods like 'pm2', 'systemd', or 'next start'. Avoid 'npm run dev' on production servers.",
                    impact=["Significant performance overhead", "Increased attack surface (dev tools/logs exposed)", "Process instability"],
                    correlation=self._get_correlations(str(proc.pid))
                ))
        return findings

    def _check_environment_sources(self) -> list[Finding]:
        """Check if Node projects have an obvious environment source (NODE-2)."""
        findings: list[Finding] = []
        
        # This check is more project-centric
        for project in self.model.projects:
            if "NODE" in project.type.name or project.type.name in ("NEXTJS", "NUXT"):
                # Potential sources: .env, systemd unit, docker env, pm2 (we'd need more data for pm2)
                sources = []
                if project.env_path:
                    sources.append(".env file")
                
                # Check if it's dockerized
                if project.docker_container:
                    sources.append("Docker environment variables")

                if not sources:
                    findings.append(Finding(
                        severity=Severity.WARNING,
                        confidence=0.7,
                        condition=f"No obvious environment configuration source for {project.type.value} project",
                        cause=f"Project at {project.path} has no .env file and isn't obviously managed by Docker/Systemd with env vars.",
                        evidence=[Evidence(
                            source_file=project.path,
                            line_number=1,
                            excerpt="Missing .env and other common sources",
                            command="ls -a"
                        )],
                        treatment="Ensure environment variables are explicitly defined in a .env file, systemd unit, or CI/CD secrets.",
                        impact=["Undefined behavior due to missing config", "Security risks from default/fallback values"]
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
