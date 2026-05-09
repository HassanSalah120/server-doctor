import pytest
from dataclasses import dataclass
from server_doctor.engine.remediation import RemediationGenerator
from server_doctor.model.server import ServerModel, NginxInfo, ServiceStatus, CapabilityLevel, ServicesModel, RuntimeModel

@pytest.fixture
def docker_topology():
    topology = ServerModel(
        hostname="docker-host",
        nginx=NginxInfo(version="1.24.0", config_path="/etc/nginx/nginx.conf"),
        nginx_status=ServiceStatus(capability=CapabilityLevel.FULL)
    )
    
    @dataclass
    class Container:
        name: str
        image: str
    
    @dataclass
    class Services:
        docker_containers: list
    
    topology.services = ServicesModel()
    topology.services.docker_containers = [Container(name="my-nginx", image="nginx:latest")]
    return topology

@pytest.fixture
def systemd_topology():
    topology = ServerModel(
        hostname="ubuntu-host",
        nginx=NginxInfo(version="1.24.0", config_path="/etc/nginx/nginx.conf"),
        nginx_status=ServiceStatus(capability=CapabilityLevel.FULL)
    )
    
    @dataclass
    class Service:
        name: str
    
    topology.runtime = RuntimeModel()
    topology.runtime.systemd_services = [Service(name="nginx.service")]
    return topology

def test_docker_commands(docker_topology):
    gen = RemediationGenerator(docker_topology)
    assert gen.is_docker is True
    assert "docker exec my-nginx nginx -s reload" == gen.get_reload_command()
    assert "docker exec my-nginx nginx -t" == gen.get_test_command()

def test_systemd_commands(systemd_topology):
    gen = RemediationGenerator(systemd_topology)
    assert gen.is_systemd is True
    assert "systemctl reload nginx" == gen.get_reload_command()

def test_wrap_fix(docker_topology):
    gen = RemediationGenerator(docker_topology)
    fix = "Run reload Nginx after changes."
    wrapped = gen.wrap_fix(fix)
    assert "`docker exec my-nginx nginx -s reload`" in wrapped
