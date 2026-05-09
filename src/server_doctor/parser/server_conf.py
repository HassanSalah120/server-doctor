"""Nginx Configuration Parser.

Parses the output of `nginx -T` into structured ServerBlock and LocationBlock objects.
Most importantly, tracks line numbers for every directive to support evidence-based findings.

IMPORTANT DESIGN NOTES:
1. Nginx configs can be nested hell with includes
2. This parser preserves FINAL RESOLVED values, not just first seen
3. Line numbers are tracked relative to the flattened nginx -T output
4. Source file paths are extracted from nginx -T comments
"""

import re
from dataclasses import dataclass, field

from server_doctor.model.server import LocationBlock, NginxInfo, ServerBlock, UpstreamBlock


@dataclass
class ParsedDirective:
    """A parsed nginx directive with source tracking."""

    name: str
    args: list[str]
    line_number: int
    source_file: str = ""
    raw_line: str = ""


@dataclass
class ParseContext:
    """Context during parsing to track current position."""

    current_file: str = ""
    in_server: bool = False
    in_location: bool = False
    in_upstream: bool = False
    in_map: bool = False
    brace_depth: int = 0
    server_brace_depth: int = 0
    location_brace_depth: int = 0


class NginxConfigParser:
    """Parser for nginx -T output.

    Converts the flat configuration dump into structured objects
    while preserving source file and line number information.
    """

    # Regex to match nginx -T file headers
    # Example: # configuration file /etc/nginx/nginx.conf:
    FILE_HEADER_RE = re.compile(r"^# configuration file (.*):")

    # Regex to match simple directives
    # Example: server_name example.com www.example.com;
    DIRECTIVE_RE = re.compile(r"^\s*(\w+)\s+(.+?);?\s*$")

    def __init__(self) -> None:
        self.errors: list[str] = []

    def parse(self, nginx_t_output: str, version: str = "") -> NginxInfo:
        """Parse nginx -T output into NginxInfo structure.

        Args:
            nginx_t_output: Full output from nginx -T command.
            version: Nginx version string.

        Returns:
            NginxInfo with all parsed server blocks.
        """
        info = NginxInfo(version=version, config_path="", raw=nginx_t_output)
        ctx = ParseContext()

        lines = nginx_t_output.split("\n")
        current_server: ServerBlock | None = None
        current_location: LocationBlock | None = None
        current_upstream: UpstreamBlock | None = None

        for line_num, line in enumerate(lines, start=1):
            stripped = line.strip()

            # Track which file we're in
            file_match = self.FILE_HEADER_RE.match(stripped)
            if file_match:
                ctx.current_file = file_match.group(1)
                if not info.config_path and "nginx.conf" in ctx.current_file:
                    info.config_path = ctx.current_file
                if ctx.current_file not in info.includes:
                    info.includes.append(ctx.current_file)
                if ctx.current_file not in info.virtual_files:
                    info.virtual_files[ctx.current_file] = ""
                continue

            # Store line in virtual files if we have a current file
            if ctx.current_file:
                info.virtual_files[ctx.current_file] += line + "\n"

            # Skip comments and empty lines
            if not stripped or stripped.startswith("#"):
                continue

            # Detect map block for $connection_upgrade (WS best practice)
            if stripped.startswith("map ") and "$http_upgrade" in stripped and "$connection_upgrade" in stripped:
                info.has_connection_upgrade_map = True
                ctx.in_map = True
                continue
            
            # Track map block end
            if ctx.in_map:
                if stripped == "}":
                    ctx.in_map = False
                continue

            # Detect upstream block start
            if stripped.startswith("upstream") and "{" in stripped:
                upstream_match = re.match(r"upstream\s+(\S+)\s*\{", stripped)
                upstream_name = upstream_match.group(1) if upstream_match else "unknown"
                current_upstream = UpstreamBlock(
                    name=upstream_name,
                    source_file=ctx.current_file,
                    line_number=line_num,
                )
                ctx.in_upstream = True
                continue

            # Handle upstream block content
            if ctx.in_upstream:
                if stripped == "}":
                    if current_upstream:
                        info.upstreams.append(current_upstream)
                    current_upstream = None
                    ctx.in_upstream = False
                elif stripped.startswith("server"):
                    # Parse upstream server: "server 127.0.0.1:6001;"
                    server_match = re.match(r"server\s+([^;]+)", stripped)
                    if server_match and current_upstream:
                        current_upstream.servers.append(server_match.group(1).strip())
                continue

            # Global/HTTP context directives
            if not ctx.in_server and not ctx.in_upstream and not ctx.in_map:
                if stripped.startswith("add_header "):
                    parts = stripped.rstrip(";").split(None, 2)
                    if len(parts) >= 3:
                        # add_header Name Value;
                        info.http_headers[parts[1]] = parts[2]
                elif stripped.startswith("add_header_inherit "):
                    parts = stripped.rstrip(";").split(None, 1)
                    if len(parts) == 2:
                        info.http_add_header_inherit = parts[1].strip()

            # Track brace depth for context
            open_braces = stripped.count("{")
            close_braces = stripped.count("}")
            
            # Detect server block start
            if not ctx.in_server and stripped.startswith("server") and "{" in stripped:
                current_server = ServerBlock(
                    source_file=ctx.current_file,
                    line_number=line_num,
                )
                ctx.in_server = True
                ctx.server_brace_depth = ctx.brace_depth
                ctx.brace_depth += open_braces - close_braces
                continue

            # Detect location block start
            if ctx.in_server and not ctx.in_location and stripped.startswith("location") and "{" in stripped:
                # Extract location path
                loc_match = re.match(r"location\s+(.*?)\s*\{", stripped)
                loc_path = loc_match.group(1) if loc_match else ""
                current_location = LocationBlock(
                    path=loc_path.strip(),
                    line_number=line_num,
                    source_file=ctx.current_file
                )
                ctx.in_location = True
                ctx.location_brace_depth = ctx.brace_depth
                ctx.brace_depth += open_braces - close_braces
                continue

            # Update depth for other lines
            old_depth = ctx.brace_depth
            ctx.brace_depth += open_braces - close_braces

            # Detect location block end
            if ctx.in_location and stripped == "}" and ctx.brace_depth == ctx.location_brace_depth:
                if current_location and current_server:
                    current_server.locations.append(current_location)
                current_location = None
                ctx.in_location = False
                continue

            # Detect server block end
            if ctx.in_server and stripped == "}" and ctx.brace_depth == ctx.server_brace_depth:
                if current_server:
                    info.servers.append(current_server)
                current_server = None
                ctx.in_server = False
                continue

            # Parse directives within server/location blocks
            if current_server:
                self._parse_directive(stripped, line_num, current_server, current_location)

        return info

    def _parse_directive(
        self,
        line: str,
        line_num: int,
        server: ServerBlock,
        location: LocationBlock | None,
    ) -> None:
        """Parse a single directive line.

        Args:
            line: The directive line (stripped).
            line_num: Line number in the nginx -T output.
            server: Current server block being parsed.
            location: Current location block (if inside one).
        """
        # Remove trailing semicolon and split
        line = line.rstrip(";").strip()
        if not line or line.startswith("#"):
            return

        parts = line.split(None, 1)
        if len(parts) < 1:
            return

        directive = parts[0].lower()
        args = parts[1] if len(parts) > 1 else ""

        # Server-level directives
        if location is None:
            if directive == "server_name":
                server.server_names = [n.strip() for n in args.split() if n.strip()]
            elif directive == "listen":
                server.listen.append(args)
                if "ssl" in args.lower():
                    server.ssl_enabled = True
            elif directive == "http2":
                server.http2_enabled = args.strip().lower() == "on"
            elif directive == "root":
                server.root = args.strip()
            elif directive == "autoindex":
                server.autoindex = args.strip().lower() == "on"
            elif directive == "index":
                server.index = [i.strip() for i in args.split() if i.strip()]
            elif directive == "ssl_certificate":
                server.ssl_certificate = args.strip()
            elif directive == "ssl_certificate_key":
                server.ssl_certificate_key = args.strip()
            elif directive == "add_header":
                header_parts = args.split(None, 1)
                if len(header_parts) == 2:
                    server.headers[header_parts[0]] = header_parts[1]
            elif directive == "add_header_inherit":
                server.add_header_inherit = args.strip()
            elif directive == "auth_basic":
                server.auth_basic = args.strip()
            elif directive == "include":
                include_path = args.strip()
                if include_path:
                    server.include_files.append(include_path)
            elif directive == "allow":
                rule = args.strip()
                if rule:
                    server.allow_rules.append(rule)
            elif directive == "deny":
                rule = args.strip()
                if rule:
                    server.deny_rules.append(rule)
        else:
            # Location-level directives
            if directive == "root":
                location.root = args.strip()
            elif directive == "alias":
                location.alias = args.strip()
            elif directive == "try_files":
                location.try_files = args.strip()
            elif directive == "fastcgi_pass":
                location.fastcgi_pass = args.strip()
            elif directive == "proxy_pass":
                location.proxy_pass = args.strip()
            elif directive == "add_header":
                header_parts = args.split(None, 1)
                if len(header_parts) == 2:
                    location.headers[header_parts[0]] = header_parts[1]
            elif directive == "add_header_inherit":
                location.add_header_inherit = args.strip()
            elif directive == "auth_basic":
                location.auth_basic = args.strip()
            elif directive == "include":
                include_path = args.strip()
                if include_path:
                    location.include_files.append(include_path)
            elif directive == "allow":
                rule = args.strip()
                if rule:
                    location.allow_rules.append(rule)
            elif directive == "deny":
                rule = args.strip()
                if rule:
                    location.deny_rules.append(rule)
            # WebSocket / Reverse Proxy directives
            elif directive == "proxy_http_version":
                location.proxy_http_version = args.strip()
            elif directive == "proxy_set_header":
                # Parse: proxy_set_header Upgrade $http_upgrade;
                header_parts = args.split(None, 1)
                if len(header_parts) == 2:
                    location.proxy_set_headers[header_parts[0]] = header_parts[1]
            elif directive == "proxy_buffering":
                location.proxy_buffering = args.strip()
            elif directive == "proxy_read_timeout":
                # Parse timeout value (may have 's' suffix or just number)
                timeout_str = args.strip().rstrip('s')
                try:
                    location.proxy_read_timeout = int(timeout_str)
                except ValueError:
                    pass
            elif directive == "proxy_send_timeout":
                timeout_str = args.strip().rstrip('s')
                try:
                    location.proxy_send_timeout = int(timeout_str)
                except ValueError:
                    pass
            elif directive == "return":
                location.return_directive = args.strip()
            elif directive == "stub_status":
                location.stub_status = args.strip().lower() == "on"

    def get_directive_at_line(
        self, nginx_t_output: str, line_number: int
    ) -> tuple[str, str] | None:
        """Get the source file and content for a specific line.

        Used for generating evidence.

        Args:
            nginx_t_output: Full nginx -T output.
            line_number: Line number to look up.

        Returns:
            Tuple of (source_file, line_content) or None.
        """
        lines = nginx_t_output.split("\n")
        if line_number < 1 or line_number > len(lines):
            return None

        # Work backwards to find the source file
        source_file = ""
        for i in range(line_number - 1, -1, -1):
            match = self.FILE_HEADER_RE.match(lines[i].strip())
            if match:
                source_file = match.group(1)
                break

        return (source_file, lines[line_number - 1])
