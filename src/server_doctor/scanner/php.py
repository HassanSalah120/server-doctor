"""PHP Scanner - Collects PHP installation and FPM information.

This scanner finds PHP versions, FPM sockets, and pool configurations.
"""

from dataclasses import dataclass, field

from server_doctor.connector.ssh import SSHConnector


@dataclass
class PHPScanResult:
    """Raw PHP scan results."""

    installed: bool = False
    versions: list[str] = field(default_factory=list)
    default_version: str = ""
    cli_version: str = ""
    fpm_sockets: list[str] = field(default_factory=list)
    fpm_running: bool = False
    pool_configs: list[str] = field(default_factory=list)


class PHPScanner:
    """Scanner for PHP installation and FPM configuration.

    Collects:
    - Installed PHP versions
    - Default PHP version
    - FPM socket paths
    - FPM pool configurations
    """

    # Common socket locations to check
    SOCKET_PATHS = [
        "/run/php",
        "/var/run/php",
        "/var/run/php-fpm",
    ]

    # Common PHP binary locations
    PHP_BINARIES = [
        "/usr/bin/php",
        "/usr/bin/php8.3",
        "/usr/bin/php8.2",
        "/usr/bin/php8.1",
        "/usr/bin/php8.0",
        "/usr/bin/php7.4",
    ]

    def __init__(self, ssh: SSHConnector) -> None:
        self.ssh = ssh

    def scan(self) -> PHPScanResult:
        """Perform full PHP scan.

        Returns:
            PHPScanResult with all collected data.
        """
        result = PHPScanResult()

        # Check default PHP version
        version_result = self.ssh.run("php -v", timeout=5, use_sudo=False)
        if version_result.success:
            result.installed = True
            # Parse version from "PHP 8.2.10 (cli) ..."
            first_line = version_result.stdout.split("\n")[0]
            if first_line.startswith("PHP "):
                result.cli_version = first_line.split()[1]
                result.default_version = result.cli_version
                result.versions.append(result.cli_version)

        # Find all installed PHP versions
        installed_versions = self._find_installed_versions()
        for ver in installed_versions:
            if ver not in result.versions:
                result.versions.append(ver)

        # Find FPM sockets
        result.fpm_sockets = self._find_fpm_sockets()

        # Check if FPM is running
        fpm_check = self.ssh.run("pgrep -x php-fpm", timeout=5)
        result.fpm_running = fpm_check.success

        # Find pool configurations
        result.pool_configs = self._find_pool_configs()

        return result

    def _find_installed_versions(self) -> list[str]:
        """Find all installed PHP versions."""
        versions: list[str] = []

        # Check for versioned PHP binaries
        result = self.ssh.run(
            "ls /usr/bin/php* 2>/dev/null | grep -E 'php[0-9]'",
            timeout=5,
            use_sudo=False,
        )
        if result.success:
            for binary in result.stdout.strip().split("\n"):
                # Extract version from path like /usr/bin/php8.2
                binary = binary.strip()
                if binary:
                    ver_result = self.ssh.run(
                        f"{binary} -v 2>/dev/null | head -1",
                        timeout=5,
                        use_sudo=False,
                    )
                    if ver_result.success and "PHP " in ver_result.stdout:
                        version = ver_result.stdout.split()[1]
                        if version not in versions:
                            versions.append(version)

        return versions

    def _find_fpm_sockets(self) -> list[str]:
        """Find all PHP-FPM socket files and canonicalize them."""
        sockets: list[str] = []

        for socket_dir in self.SOCKET_PATHS:
            if not self.ssh.dir_exists(socket_dir):
                continue

            result = self.ssh.run(
                f"find {socket_dir} -name '*.sock' 2>/dev/null",
                timeout=6,
            )
            if result.success:
                for sock in result.stdout.strip().split("\n"):
                    sock = sock.strip()
                    if sock:
                        # Canonicalize /var/run to /run
                        if sock.startswith("/var/run/"):
                            sock = sock.replace("/var/run/", "/run/", 1)
                        
                        if sock not in sockets:
                            sockets.append(sock)

        return sorted(list(set(sockets)))

    def _find_pool_configs(self) -> list[str]:
        """Find PHP-FPM pool configuration files."""
        configs: list[str] = []

        # Common locations for pool configs
        pool_dirs = [
            "/etc/php/*/fpm/pool.d",
            "/etc/php-fpm.d",
        ]

        for pattern in pool_dirs:
            result = self.ssh.run(f"ls {pattern}/*.conf 2>/dev/null", timeout=6)
            if result.success:
                for conf in result.stdout.strip().split("\n"):
                    conf = conf.strip()
                    if conf and conf not in configs:
                        configs.append(conf)

        return configs
