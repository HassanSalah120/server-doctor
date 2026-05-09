import json
from dataclasses import asdict
from server_doctor.model.server import ServerModel, OSInfo, NginxInfo, PHPInfo, NodeProcess, DockerContainer
from server_doctor.model.finding import Finding
from server_doctor.model.evidence import Evidence, Severity
from jinja2 import Environment, FileSystemLoader
import os

def test_report_visuals():
    # Mock data
    os_info = OSInfo(name="Ubuntu", version="22.04", codename="jammy")
    nginx_info = NginxInfo(version="1.18.0", mode="System", config_path="/etc/nginx/nginx.conf")
    
    evidence = [Evidence(source_file="/etc/nginx/nginx.conf", line_number=1, command="test", excerpt="test")]
    
    findings = [
        Finding(
            id="CRIT-001",
            severity=Severity.CRITICAL,
            condition="Critical Issue",
            cause="Testing critical",
            treatment="Fix it",
            confidence=1.0,
            evidence=evidence
        ),
        Finding(
            id="WARN-001",
            severity=Severity.WARNING,
            condition="Warning Issue",
            cause="Testing warning",
            treatment="Fix it",
            confidence=0.8,
            evidence=evidence
        ),
        Finding(
            id="INFO-001",
            severity=Severity.INFO,
            condition="Info Issue",
            cause="Testing info",
            treatment="Read it",
            confidence=0.9,
            evidence=evidence
        )
    ]
    
    model = ServerModel(
        hostname="test-server",
        os=os_info,
        nginx=nginx_info,
        projects=[]
    )
    
    # Load template
    template_dir = os.path.join("src", "server_doctor", "templates")
    env = Environment(loader=FileSystemLoader(template_dir))
    template = env.get_template("report.html")
    
    # Render
    output = template.render(
        model=model,
        findings=findings,
        now="2026-02-08 01:45:00"
    )
    
    with open("debug_report.html", "w") as f:
        f.write(output)
    print("Debug report generated: debug_report.html")

if __name__ == "__main__":
    test_report_visuals()
