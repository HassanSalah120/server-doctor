"""Tests for ServerAuditor environment exposure."""

import sys
from pathlib import Path
from unittest.mock import MagicMock

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from server_doctor.analyzer.server_auditor import ServerAuditor
from server_doctor.model.server import ServerModel, ProjectInfo, ProjectType, NginxInfo, ServerBlock
from server_doctor.model.evidence import Severity


def make_model_with_env(root_path: str, env_path: str, protected: bool) -> ServerModel:
    model = ServerModel(hostname="test")
    # create dummy project
    proj = ProjectInfo(path=root_path, type=ProjectType.LARAVEL, confidence=1.0)
    proj.env_path = env_path
    model.projects.append(proj)

    nginx = NginxInfo(version="1.20", config_path="/etc/nginx/nginx.conf")
    server = ServerBlock(server_names=["example.com"], listen=["80"])
    server.root = root_path
    if protected:
        # add a dotfile location to simulate deny rule
        server.locations = [
            type("L", (), {"path": r"/\\.", "source_file": "/etc/nginx/nginx.conf", "line_number": 10})()
        ]
        # our naive protection check also looks at raw config for "deny all"
        nginx.raw = "deny all"
    else:
        nginx.raw = ""
    nginx.servers = [server]
    model.nginx = nginx
    return model


def test_env_exposure_critical():
    # env in root without protection should be critical severity
    model = make_model_with_env("/var/www/app", "/var/www/app/.env", protected=False)
    findings = ServerAuditor(model).audit()
    assert any(f.condition == ".env file may be exposed" and f.severity == Severity.CRITICAL for f in findings)

    # with protection severity should drop (no finding)
    model2 = make_model_with_env("/var/www/app", "/var/www/app/.env", protected=True)
    findings2 = ServerAuditor(model2).audit()
    assert not any(f.condition == ".env file may be exposed" for f in findings2)


def test_env_outside_root_with_compliant_permissions_is_not_flagged():
    model = ServerModel(hostname="test")
    proj = ProjectInfo(path="/var/www/app", type=ProjectType.LARAVEL, confidence=1.0)
    proj.env_path = "/var/www/app/.env"
    proj.env_permissions = "600"
    model.projects.append(proj)

    nginx = NginxInfo(version="1.20", config_path="/etc/nginx/nginx.conf")
    server = ServerBlock(server_names=["example.com"], listen=["80"])
    server.root = "/var/www/app/public"
    nginx.servers = [server]
    model.nginx = nginx

    findings = ServerAuditor(model).audit()
    assert not any(f.condition == ".env file exists (likely safe)" for f in findings)


def test_env_outside_root_with_broad_permissions_is_flagged():
    model = ServerModel(hostname="test")
    proj = ProjectInfo(path="/var/www/app", type=ProjectType.LARAVEL, confidence=1.0)
    proj.env_path = "/var/www/app/.env"
    proj.env_permissions = "644"
    model.projects.append(proj)

    nginx = NginxInfo(version="1.20", config_path="/etc/nginx/nginx.conf")
    server = ServerBlock(server_names=["example.com"], listen=["80"])
    server.root = "/var/www/app/public"
    nginx.servers = [server]
    model.nginx = nginx

    findings = ServerAuditor(model).audit()
    info_findings = [f for f in findings if f.condition == ".env file exists (likely safe)"]
    assert info_findings
