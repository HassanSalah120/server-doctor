"""Pytest configuration and fixtures for server-doctor tests."""

import pytest
from unittest.mock import MagicMock

from server_doctor.connector.ssh import SSHConfig, SSHConnector, CommandResult
from server_doctor.model.server import ServerModel, OSInfo


@pytest.fixture
def mock_ssh_connector():
    """Create a mock SSH connector for testing."""
    connector = MagicMock(spec=SSHConnector)
    
    # Default behavior: commands succeed
    connector.run.return_value = CommandResult(
        command="test",
        stdout="",
        stderr="",
        exit_code=0,
    )
    connector.file_exists.return_value = True
    connector.dir_exists.return_value = True
    connector.list_dir.return_value = []
    
    return connector


@pytest.fixture
def sample_nginx_t_output():
    """Sample nginx -T output for parser testing."""
    return '''# configuration file /etc/nginx/nginx.conf:
user www-data;
worker_processes auto;

events {
    worker_connections 768;
}

http {
    include /etc/nginx/mime.types;
    include /etc/nginx/sites-enabled/*;
}

# configuration file /etc/nginx/sites-enabled/default:
server {
    listen 80 default_server;
    server_name _;
    root /var/www/html;
    index index.html;
}

# configuration file /etc/nginx/sites-enabled/laravel.conf:
server {
    listen 80;
    server_name laravel.example.com;
    root /var/www/laravel;
    index index.php;
    
    location / {
        try_files $uri $uri/ /index.php?$query_string;
    }
    
    location ~ \\.php$ {
        fastcgi_pass unix:/run/php/php8.2-fpm.sock;
        fastcgi_param SCRIPT_FILENAME $realpath_root$fastcgi_script_name;
        include fastcgi_params;
    }
}
'''


@pytest.fixture
def sample_server_model():
    """Create a sample server model for testing."""
    return ServerModel(
        hostname="test-server",
        os=OSInfo(name="Ubuntu", version="22.04", codename="jammy"),
    )
