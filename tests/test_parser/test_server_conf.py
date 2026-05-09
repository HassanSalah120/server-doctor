"""Tests for the nginx configuration parser."""

import pytest

from server_doctor.parser.nginx_conf import NginxConfigParser


class TestNginxConfigParser:
    """Test nginx -T output parsing."""

    def test_parse_extracts_version(self, sample_nginx_t_output):
        """Parser should preserve version passed to it."""
        parser = NginxConfigParser()
        info = parser.parse(sample_nginx_t_output, version="1.24.0")
        
        assert info.version == "1.24.0"

    def test_parse_extracts_config_path(self, sample_nginx_t_output):
        """Parser should extract main config path."""
        parser = NginxConfigParser()
        info = parser.parse(sample_nginx_t_output)
        
        assert "nginx.conf" in info.config_path

    def test_parse_finds_server_blocks(self, sample_nginx_t_output):
        """Parser should find all server blocks."""
        parser = NginxConfigParser()
        info = parser.parse(sample_nginx_t_output)
        
        assert len(info.servers) >= 2

    def test_parse_tracks_source_files(self, sample_nginx_t_output):
        """Parser should track which file each block came from."""
        parser = NginxConfigParser()
        info = parser.parse(sample_nginx_t_output)
        
        # At least one server should have source file tracked
        servers_with_source = [s for s in info.servers if s.source_file]
        assert len(servers_with_source) > 0

    def test_parse_extracts_server_names(self, sample_nginx_t_output):
        """Parser should extract server_name directives."""
        parser = NginxConfigParser()
        info = parser.parse(sample_nginx_t_output)
        
        all_names = []
        for server in info.servers:
            all_names.extend(server.server_names)
        
        assert "_" in all_names or "laravel.example.com" in all_names

    def test_parse_extracts_locations(self, sample_nginx_t_output):
        """Parser should extract location blocks."""
        parser = NginxConfigParser()
        info = parser.parse(sample_nginx_t_output)
        
        # Find server with locations
        servers_with_locations = [s for s in info.servers if s.locations]
        assert len(servers_with_locations) > 0

    def test_parse_tracks_line_numbers(self, sample_nginx_t_output):
        """Parser should track line numbers for evidence."""
        parser = NginxConfigParser()
        info = parser.parse(sample_nginx_t_output)
        
        # Server blocks should have line numbers
        for server in info.servers:
            assert server.line_number > 0

    def test_parse_collects_includes(self, sample_nginx_t_output):
        """Parser should track all included files."""
        parser = NginxConfigParser()
        info = parser.parse(sample_nginx_t_output)
        
        assert len(info.includes) > 0

    def test_parse_location_allow_deny_and_include(self):
        parser = NginxConfigParser()
        nginx_t = """# configuration file /etc/nginx/conf.d/default.conf:
server {
    listen 443 ssl;
    location /admin/ {
        allow 127.0.0.1;
        deny all;
        include /etc/nginx/conf.d/security_headers.inc;
    }
}
"""
        info = parser.parse(nginx_t)
        assert len(info.servers) == 1
        assert len(info.servers[0].locations) == 1
        loc = info.servers[0].locations[0]
        assert "127.0.0.1" in loc.allow_rules
        assert "all" in loc.deny_rules
        assert "/etc/nginx/conf.d/security_headers.inc" in loc.include_files

    def test_parse_server_level_http2_and_access_rules(self):
        parser = NginxConfigParser()
        nginx_t = """# configuration file /etc/nginx/conf.d/default.conf:
server {
    listen 443 ssl;
    http2 on;
    allow 127.0.0.1;
    deny all;
}
"""
        info = parser.parse(nginx_t)
        assert len(info.servers) == 1
        server = info.servers[0]
        assert server.http2_enabled is True
        assert "127.0.0.1" in server.allow_rules
        assert "all" in server.deny_rules

    def test_parse_auth_basic_and_add_header_inherit(self):
        parser = NginxConfigParser()
        nginx_t = """# configuration file /etc/nginx/nginx.conf:
add_header_inherit merge;
# configuration file /etc/nginx/conf.d/default.conf:
server {
    listen 443 ssl;
    auth_basic "Restricted";
    add_header_inherit off;
    location /admin/ {
        auth_basic off;
        add_header_inherit merge;
    }
}
"""
        info = parser.parse(nginx_t)
        assert info.http_add_header_inherit == "merge"
        assert len(info.servers) == 1
        server = info.servers[0]
        assert server.auth_basic == '"Restricted"'
        assert server.add_header_inherit == "off"
        assert len(server.locations) == 1
        loc = server.locations[0]
        assert loc.auth_basic == "off"
        assert loc.add_header_inherit == "merge"
