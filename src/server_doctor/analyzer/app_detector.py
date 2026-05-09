"""App Detector - Detects and classifies web applications.

Determines project types (Laravel, PHP MVC, Static, etc.) based on
filesystem structure collected by the scanner.
"""

from dataclasses import dataclass
from typing import TYPE_CHECKING
import json

from server_doctor.model.server import ProjectInfo, ProjectType
from server_doctor.scanner.filesystem import DirectoryScan

if TYPE_CHECKING:
    from server_doctor.model.server import DockerContainer


@dataclass
class DetectionResult:
    """Result of app detection."""

    project_type: ProjectType
    confidence: float
    reasons: list[str]
    framework_version: str | None = None


class AppDetector:
    """Detects application frameworks from filesystem scans.

    Does NOT run shell commands - operates on DirectoryScan data only.
    """

    def detect(
        self,
        scan: DirectoryScan,
        composer_json: dict | None = None,
        package_json: dict | None = None,
        docker_containers: list["DockerContainer"] | None = None,
    ) -> DetectionResult:
        """Detect the application type from a directory scan.

        Args:
            scan: DirectoryScan from the filesystem scanner.
            composer_json: Parsed composer.json if available.

        Returns:
            DetectionResult with type, confidence, and reasons.
        """
        reasons: list[str] = []
        confidence = 0.0
        project_type = ProjectType.UNKNOWN
        framework_version: str | None = None

        # Check for Laravel
        if scan.has_artisan:
            project_type = ProjectType.LARAVEL
            confidence = 0.90
            reasons.append("Found 'artisan' file (Laravel CLI)")

            if scan.has_public_dir:
                confidence += 0.02
                reasons.append("Has 'public/' directory")
            
            if scan.has_bootstrap_dir:
                confidence += 0.02
                reasons.append("Has 'bootstrap/' directory")
            
            if scan.has_routes_dir:
                confidence += 0.02
                reasons.append("Has 'routes/' directory")
            
            if scan.has_storage_dir:
                confidence += 0.01
                reasons.append("Has 'storage/' directory")
            
            if scan.has_app_dir:
                confidence += 0.01
                reasons.append("Has 'app/' directory")

            if composer_json:
                if self._has_laravel_dependency(composer_json):
                    confidence = min(confidence + 0.02, 1.0)
                    reasons.append("composer.json contains laravel/framework")
                    framework_version = self._get_laravel_version(composer_json)

            return DetectionResult(
                project_type=project_type,
                confidence=min(confidence, 1.0),
                reasons=reasons,
                framework_version=framework_version,
            )


        # Check for generic PHP project
        if scan.has_composer_json or scan.has_index_php:
            project_type = ProjectType.PHP_MVC
            confidence = 0.70
            reasons.append("PHP project detected")

            if scan.has_composer_json:
                reasons.append("Has composer.json")
                confidence += 0.10

            if scan.has_public_dir:
                reasons.append("Has public/ directory (MVC pattern)")
                confidence += 0.10

            return DetectionResult(
                project_type=project_type,
                confidence=confidence,
                reasons=reasons,
            )

        # Check for static site
        if scan.has_index_html:
            # Distinguish between plain static and React static build
            if scan.has_dist_dir or scan.has_build_dir or scan.has_out_dir:
                project_type = ProjectType.REACT_STATIC_BUILD
                confidence = 0.90
                reasons.append("Detected static HTML with build artifacts (dist/build/out)")
                
                if package_json and "react" in str(package_json.get("dependencies", {})):
                    reasons.append("package.json confirms React dependency")
                    confidence += 0.05
            else:
                project_type = ProjectType.STATIC
                confidence = 0.95
                reasons.append("Static HTML site (has index.html)")

            return DetectionResult(
                project_type=project_type,
                confidence=confidence,
                reasons=reasons,
            )

        # Check for JS / Node projects
        if scan.has_package_json:
            confidence = 0.70
            reasons.append("Found package.json (JavaScript project)")
            
            if package_json:
                deps = package_json.get("dependencies", {})
                scripts = package_json.get("scripts", {})
                dep_keys = set(deps.keys())
                script_text = " ".join(str(v) for v in scripts.values()).lower()
                has_ws_stack = any(k in dep_keys for k in {"ws", "socket.io", "uwebsockets.js"})
                is_react = "react" in dep_keys
                is_node_api = any(k in dep_keys for k in {"express", "fastify", "koa", "hono"})
                
                if "next" in deps:
                    project_type = ProjectType.NEXTJS
                    confidence = 0.95
                    reasons.append("Next.js dependency detected")
                elif "nuxt" in deps or "nuxt3" in deps:
                    project_type = ProjectType.NUXT
                    confidence = 0.95
                    reasons.append("Nuxt.js dependency detected")
                elif is_react and ("vite" in dep_keys or "react-scripts" in dep_keys or "webpack" in dep_keys):
                    project_type = ProjectType.REACT_FRONTEND
                    confidence = 0.90
                    reasons.append("React frontend build stack detected")
                elif is_react:
                    # If it has package.json and react but no index.html in root, likely source
                    project_type = ProjectType.REACT_SOURCE
                    reasons.append("React dependency in source form")
                elif has_ws_stack and ("ws" in script_text or "socket" in script_text):
                    project_type = ProjectType.WEBSOCKET_SERVICE
                    confidence = 0.88
                    reasons.append("WebSocket service dependencies/scripts detected")
                elif is_node_api:
                    project_type = ProjectType.NODE_API
                    reasons.append("Node.js API framework detected (Express/Fastify/Koa)")
                else:
                    project_type = ProjectType.NODE_API # Default for node apps
                    reasons.append("Generic Node.js application")

            return DetectionResult(
                project_type=project_type,
                confidence=confidence,
                reasons=reasons,
            )

        # Check for Dockerized App (Mapping detection)
        if docker_containers:
            for container in docker_containers:
                image_lower = (container.image or "").lower()
                name_lower = (container.name or "").lower()
                if any(k in image_lower or k in name_lower for k in ("nginx", "traefik", "caddy", "haproxy")):
                    for mount in container.mounts:
                        source = mount.get("source", "")
                        if source and (source == scan.path or source.startswith(scan.path + "/")):
                            return DetectionResult(
                                project_type=ProjectType.REVERSE_PROXY,
                                confidence=0.82,
                                reasons=[f"Directory mapped into reverse proxy container '{container.name}'"],
                            )
                for mount in container.mounts:
                    source = mount.get("source", "")
                    if source and (source == scan.path or source.startswith(scan.path + "/")):
                        # This directory is mounted into a container!
                        return DetectionResult(
                            project_type=ProjectType.DOCKERIZED_APP,
                            confidence=0.85,
                            reasons=[f"Directory mapped into Docker container '{container.name}'"],
                        )

        # Unknown
        return DetectionResult(
            project_type=ProjectType.UNKNOWN,
            confidence=0.30,
            reasons=["Unable to determine project type"],
        )

    def _has_laravel_dependency(self, composer_json: dict) -> bool:
        """Check if composer.json has Laravel dependency."""
        require = composer_json.get("require", {})
        return "laravel/framework" in require

    def _get_laravel_version(self, composer_json: dict) -> str | None:
        """Extract Laravel version from composer.json."""
        require = composer_json.get("require", {})
        version = require.get("laravel/framework")
        if version:
            # Clean up version constraint (^10.0 -> 10.x)
            version = version.lstrip("^~>=<")
            return f"Laravel {version}"
        return None

    def to_project_info(
        self, scan: DirectoryScan, detection: DetectionResult
    ) -> ProjectInfo:
        """Convert scan and detection result to ProjectInfo."""
        public_path = None
        if scan.has_public_dir:
            public_path = f"{scan.path}/public"

        return ProjectInfo(
            path=scan.path,
            type=detection.project_type,
            confidence=detection.confidence,
            public_path=public_path,
            framework_version=detection.framework_version,
            env_path=f"{scan.path}/.env" if scan.has_env else None,
            env_permissions=scan.env_permissions,
            docker_container=next((r.split("'")[1] for r in detection.reasons if "Docker container" in r), None)
        )
