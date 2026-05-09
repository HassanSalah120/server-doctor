"""Filesystem Scanner - Directory traversal and file detection.

This scanner collects filesystem information without analyzing it.
It finds web roots, project directories, and relevant files.
"""

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from server_doctor.connector.ssh import SSHConnector

if TYPE_CHECKING:
    from server_doctor.model.server import OSInfo


@dataclass
class FileInfo:
    """Information about a file on the remote server."""

    path: str
    exists: bool = False
    is_dir: bool = False
    size: int = 0
    permissions: str = ""


@dataclass
class DirectoryScan:
    """Result of scanning a directory."""

    path: str
    files: list[str] = field(default_factory=list)
    directories: list[str] = field(default_factory=list)
    has_artisan: bool = False  # Laravel indicator
    has_composer_json: bool = False
    has_package_json: bool = False
    has_public_dir: bool = False
    has_index_php: bool = False
    has_index_html: bool = False
    has_env: bool = False
    env_permissions: str | None = None
    # Enhanced Laravel indicators
    has_bootstrap_dir: bool = False
    has_routes_dir: bool = False
    has_storage_dir: bool = False
    has_app_dir: bool = False
    # JS / Build indicators
    has_dist_dir: bool = False
    has_build_dir: bool = False
    has_out_dir: bool = False
    has_node_modules: bool = False
    # Detected PHP socket from nginx config (if mapped)
    php_socket: str | None = None


class FilesystemScanner:
    """Scanner for filesystem inspection.

    This scanner runs commands to discover:
    - Web root directories
    - Project directories
    - Key framework files (artisan, composer.json, etc.)
    """

    # Common web root locations to check
    COMMON_WEB_ROOTS = [
        "/var/www",
        "/var/www/html",
        "/home/*/public_html",
        "/srv/www",
    ]

    def __init__(self, ssh: SSHConnector) -> None:
        self.ssh = ssh

    @staticmethod
    def _shell_quote(value: str) -> str:
        return "'" + value.replace("'", "'\"'\"'") + "'"

    def _list_top_entries(self, path: str) -> list[tuple[str, bool]]:
        """List immediate entries with type in one remote command."""
        quoted = self._shell_quote(path.rstrip("/"))
        cmd = (
            f"find {quoted} -mindepth 1 -maxdepth 1 "
            "-printf '%f\\t%y\\n' 2>/dev/null"
        )
        result = self.ssh.run(cmd, timeout=8)
        if not result.success:
            return []

        entries: list[tuple[str, bool]] = []
        for line in (result.stdout or "").splitlines():
            raw = line.strip()
            if not raw or "\t" not in raw:
                continue
            name, kind = raw.split("\t", 1)
            if not name or name in {".", ".."}:
                continue
            entries.append((name, kind == "d"))
        return entries

    def scan_directory(self, path: str) -> DirectoryScan:
        """Scan a directory for project indicators.

        Args:
            path: Directory path to scan.

        Returns:
            DirectoryScan with detected files and indicators.
        """
        scan = DirectoryScan(path=path)

        entries = self._list_top_entries(path)
        if not entries:
            return scan

        for item, is_dir in entries:
            item_path = f"{path}/{item}"

            if is_dir:
                scan.directories.append(item)
            else:
                scan.files.append(item)

            # Check for framework indicators
            if item == "artisan":
                scan.has_artisan = True
            elif item == "composer.json":
                scan.has_composer_json = True
            elif item == "package.json":
                scan.has_package_json = True
            elif item == "public" and is_dir:
                scan.has_public_dir = True
            elif item == "bootstrap" and is_dir:
                scan.has_bootstrap_dir = True
            elif item == "routes" and is_dir:
                scan.has_routes_dir = True
            elif item == "storage" and is_dir:
                scan.has_storage_dir = True
            elif item == "app" and is_dir:
                scan.has_app_dir = True
            elif item == "index.php":
                scan.has_index_php = True
            elif item == "index.html":
                scan.has_index_html = True
            elif item == ".env":
                scan.has_env = True
                perm_result = self.ssh.run(
                    f"stat -c '%a' {item_path} 2>/dev/null",
                    timeout=5,
                )
                if perm_result.success:
                    perm = (perm_result.stdout or "").strip().splitlines()
                    if perm:
                        scan.env_permissions = perm[0].strip()
            elif item == "dist" and is_dir:
                scan.has_dist_dir = True
            elif item == "build" and is_dir:
                scan.has_build_dir = True
            elif item == "out" and is_dir:
                scan.has_out_dir = True
            elif item == "node_modules" and is_dir:
                scan.has_node_modules = True


        return scan

    def find_projects(self, web_root: str = "/var/www") -> list[DirectoryScan]:
        """Find all projects under a web root.

        Args:
            web_root: Base directory to scan.

        Returns:
            List of DirectoryScan for each subdirectory.
        """
        projects: list[DirectoryScan] = []

        # Get immediate subdirectories
        result = self.ssh.run(
            f"find {self._shell_quote(web_root.rstrip('/'))} -maxdepth 1 -type d",
            timeout=8,
        )
        if not result.success:
            return projects

        dirs = [d.strip() for d in result.stdout.strip().split("\n") if d.strip() and d != web_root]

        for dir_path in dirs:
            scan = self.scan_directory(dir_path)
            projects.append(scan)

        return projects

    def get_os_info(self) -> "OSInfo":
        """Get OS information from the remote server.

        Returns:
            OSInfo with name, version, and codename.
        """
        from server_doctor.model.server import OSInfo

        os_info = OSInfo(name="Unknown", version="Unknown")

        content_result = self.ssh.run(
            "cat /etc/os-release 2>/dev/null",
            timeout=5,
            use_sudo=False,
        )
        if content_result.success and content_result.stdout:
            for line in content_result.stdout.split("\n"):
                if line.startswith("NAME="):
                    os_info.name = line.split("=")[1].strip('"')
                elif line.startswith("VERSION_ID="):
                    os_info.version = line.split("=")[1].strip('"')
                elif line.startswith("VERSION_CODENAME="):
                    os_info.codename = line.split("=")[1].strip('"')

        return os_info

    def get_file_content(self, path: str) -> str | None:
        """Read file content from remote server."""
        return self.ssh.read_file(path)
    def crawl_projects(self, base_path: str = "/var/www") -> list[str]:
        """Crawl a base directory to find headers of potential projects.
        
        Args:
            base_path: The directory to search within (depth 1).
            
        Returns:
            List of detected project paths.
        """
        projects = []
        if not self.ssh.dir_exists(base_path):
            return []
            
        result = self.ssh.run(f"ls -1F {self._shell_quote(base_path)}", timeout=8)
        if not result.success:
            return []
            
        items = result.stdout.strip().split("\n")
        for item in items:
            if not item.endswith("/"): # Skip files
                continue
            
            # Remove trailing slash
            folder_name = item.strip("/")
            
            # Skip obvious non-projects or noise if desired, but user wants visibility
            if folder_name in (".", "..", ".git"): 
                continue
                
            projects.append(f"{base_path}/{folder_name}")
            
        return projects
