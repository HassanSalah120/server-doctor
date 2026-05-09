from pathlib import Path

from server_doctor.actions.fix_pack import FixPackAction
from server_doctor.model.evidence import Evidence, Severity
from server_doctor.model.finding import Finding


def _finding(fid: str, condition: str, excerpt: str = "Port Binding: 0.0.0.0:3000 -> 3000/tcp") -> Finding:
    return Finding(
        id=fid,
        severity=Severity.WARNING,
        confidence=0.9,
        condition=condition,
        cause="cause",
        evidence=[Evidence(source_file="x", line_number=1, excerpt=excerpt, command="docker ps")],
        treatment="t",
        impact=["i"],
    )


def test_fix_pack_exports_expected_files(tmp_path: Path):
    findings = [
        _finding("SYSTEMD-1", "Service 'certbot.service' has failed", excerpt="Unit: certbot.service"),
        _finding("SSH-1", "SSH password authentication is enabled", excerpt="PasswordAuthentication yes"),
        _finding("NGX000-1", "Docker port 3000 is exposed publicly bypassing Nginx"),
        _finding("SEC-1", "Missing security headers in location '/health'"),
        _finding("VULN-1", "Large package security update surface detected"),
    ]

    result = FixPackAction().generate(findings, tmp_path / "pack")
    script = Path(result["script"])
    patch = Path(result["patch"])

    assert script.exists()
    assert patch.exists()
    assert "set -euo pipefail" in script.read_text(encoding="utf-8")
    assert "systemctl restart certbot.service" in script.read_text(encoding="utf-8")
    assert "ufw deny 3000/tcp" in script.read_text(encoding="utf-8")
    patch_text = patch.read_text(encoding="utf-8")
    assert "location ~ /\\.(?!well-known).*" in patch_text
    assert "X-Frame-Options" in patch_text
