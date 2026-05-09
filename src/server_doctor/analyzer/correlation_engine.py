"""Correlation Engine - Maps Nginx proxy targets to discovered services.

Matches Nginx proxy_pass and fastcgi_pass targets against Docker containers,
Node.js processes, and PHP sockets using normalization and fuzzy matching.
"""

import re
from server_doctor.model.server import (
    CorrelationEvidence,
    ServerModel,
    SystemdService,
)


class CorrelationEngine:
    """Engine for correlating Nginx routes with backend services.

    Matches:
    - proxy_pass http://127.0.0.1:3000 -> NodeProcess(port=3000)
    - proxy_pass http://127.0.0.1:8080 -> DockerContainer(host_port=8080)
    - proxy_pass http://upstream_name -> Upstream lookup -> server mapping
    """

    def __init__(self, model: ServerModel) -> None:
        self.model = model

    def correlate_all(self) -> None:
        """Perform full correlation and update ProjectInfo evidence."""
        if not self.model.nginx:
            return

        # 1. Expand upstreams into a lookup map
        upstream_map = self._build_upstream_map()

        # 2. Iterate through all projects and their Nginx blocks
        # Wait, correlation is usually better done Nginx-first
        for server in self.model.nginx.servers:
            for location in server.locations:
                if location.proxy_pass:
                    # Correlate Proxy Pass
                    evidence = self._correlate_target(location.proxy_pass, upstream_map, location)
                    if evidence:
                        self._attach_evidence(evidence)

    def _build_upstream_map(self) -> dict[str, list[str]]:
        """Map upstream names to their member servers."""
        mapping: dict[str, list[str]] = {}
        if not self.model.nginx:
            return mapping

        for upstream in self.model.nginx.upstreams:
            mapping[upstream.name] = upstream.servers
        return mapping

    def _correlate_target(self, target: str, upstream_map: dict[str, list[str]], location) -> list[CorrelationEvidence]:
        """Match a proxy_pass target to a service entity."""
        evidences: list[CorrelationEvidence] = []
        
        # 1. Resolve upstream if it's just a name
        # e.g. http://my_backend/api -> my_backend
        match = re.search(r"https?://([^/:\s]+)", target)
        if match:
            host_or_upstream = match.group(1)
            if host_or_upstream in upstream_map:
                for server in upstream_map[host_or_upstream]:
                    # Recursively resolve upstream servers
                    evidences.extend(self._correlate_raw_host(server, target, location))
                return evidences

        # 2. Treat as raw host/port
        evidences.extend(self._correlate_raw_host(target, target, location))
        return evidences

        return evidences

    def _correlate_raw_host(self, host_port: str, original_target: str, location) -> list[CorrelationEvidence]:
        """Correlate a raw host:port or unix:socket with services."""
        evidences: list[CorrelationEvidence] = []
        normalized = self._normalize_host_port(host_port)
        
        # Match against Docker Containers
        for container in self.model.services.docker_containers:
            for port in container.ports:
                if port.host_port and str(port.host_port) in normalized:
                    # Check if IP also matches if specified
                    if "127.0.0.1" in normalized or "localhost" in normalized or port.host_ip == "0.0.0.0":
                        evidences.append(CorrelationEvidence(
                            nginx_location=f"{location.source_file}:{location.line_number}",
                            proxy_target_raw=original_target,
                            proxy_target_normalized=normalized,
                            matched_entity=f"Docker: {container.name}",
                            match_confidence="HIGH"
                        ))

        # Match against Node Processes
        for proc in self.model.services.node_processes:
            for port in proc.listening_ports:
                if str(port) in normalized:
                    # Check if managed by systemd
                    svc = self.find_service_by_pid(proc.pid)
                    entity_name = f"Node PID: {proc.pid}"
                    if svc:
                        entity_name += f" (Systemd: {svc.name})"
                        
                    evidences.append(CorrelationEvidence(
                        nginx_location=f"{location.source_file}:{location.line_number}",
                        proxy_target_raw=original_target,
                        proxy_target_normalized=normalized,
                        matched_entity=entity_name,
                        match_confidence="HIGH"
                    ))

        # Match against Redis Instances (if Nginx proxies to Redis directly, rare but possible)
        # Or just to expose that a backend exists on this port
        if hasattr(self.model, "runtime"):
            for redis_inst in self.model.runtime.redis_instances:
                if str(redis_inst.port) in normalized:
                    evidences.append(CorrelationEvidence(
                        nginx_location=f"{location.source_file}:{location.line_number}",
                        proxy_target_raw=original_target,
                        proxy_target_normalized=normalized,
                        matched_entity=f"Redis: {redis_inst.port}",
                        match_confidence="HIGH"
                    ))
        
        return evidences

    def _normalize_host_port(self, target: str) -> str:
        """Normalize target for matching.
        
        - http://localhost:8080 -> 127.0.0.1:8080
        - unix:/tmp/sock -> /tmp/sock
        """
        # Remove protocol
        normalized = target.replace("http://", "").replace("https://", "").split("/")[0]
        # Normalize local IPs
        normalized = normalized.replace("localhost", "127.0.0.1").replace("[::1]", "127.0.0.1")
        return normalized

    def _attach_evidence(self, evidences: list[CorrelationEvidence]) -> None:
        """Attach evidence to the relevant project if possible."""
        for ev in evidences:
            # We need to find which project this belongs to
            # usually projects are identified by paths
            
            matched = False
            for project in self.model.projects:
                # If matched entity is Node PID, check CWD
                if "Node PID" in ev.matched_entity:
                    # Extract PID
                    match = re.search(r"Node PID: (\d+)", ev.matched_entity)
                    if match:
                        pid = int(match.group(1))
                        proc = next((p for p in self.model.services.node_processes if p.pid == pid), None)
                        if proc and (proc.cwd == project.path or proc.cwd.startswith(project.path + "/")):
                            project.correlation.append(ev)
                            matched = True
                
                # If matched entity is Docker, check image or linked project
                elif "Docker" in ev.matched_entity:
                    name = ev.matched_entity.split(": ")[1]
                    if project.docker_container == name:
                        project.correlation.append(ev)
                        matched = True

            # If no project matched, it's a global/detached correlation (fine, will be handled by auditors)
            pass

    def get_evidence_for_entity(self, entity_str: str) -> list[CorrelationEvidence]:
        """Find all correlation evidence linked to a specific entity name or PID.
        
        Matches if entity_str (e.g. "my-app" or "123") is in the matched_entity field.
        """
        all_ev = []
        # Check project-level correlations
        for project in self.model.projects:
            for ev in project.correlation:
                if entity_str in ev.matched_entity:
                    all_ev.append(ev)
        
        # In a more advanced version, we might have global evidences too
        return all_ev

    def find_service_by_pid(self, pid: int) -> SystemdService | None:
        """Find systemd service managing this PID."""
        if not hasattr(self.model, "runtime"):
            return None
        for svc in self.model.runtime.systemd_services:
            if svc.main_pid == pid:
                return svc
        return None
