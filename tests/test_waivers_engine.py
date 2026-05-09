from pathlib import Path

from server_doctor.engine.waivers import apply_waivers, load_waiver_rules
from server_doctor.model.evidence import Evidence, Severity
from server_doctor.model.finding import Finding


def _finding(fid: str, condition: str = "condition") -> Finding:
    return Finding(
        id=fid,
        severity=Severity.WARNING,
        confidence=0.9,
        condition=condition,
        cause="cause",
        evidence=[Evidence(source_file="x", line_number=1, excerpt="e")],
        treatment="t",
        impact=["i"],
    )


def test_load_and_apply_waivers(tmp_path: Path):
    waiver_file = tmp_path / "waivers.yaml"
    waiver_file.write_text(
        """
waivers:
  - id: NGX000
    reason: accepted public dev port
  - id: SSH-1
    condition_contains: password authentication
    reason: temporary exception
""".strip(),
        encoding="utf-8",
    )

    rules = load_waiver_rules(waiver_file)
    findings = [
        _finding("NGX000-1", "Docker port 3000 is exposed"),
        _finding("SSH-1", "SSH password authentication is enabled"),
        _finding("SEC-1", "Missing security header"),
    ]

    kept, suppressed = apply_waivers(findings, rules)
    kept_ids = {f.id for f in kept}
    suppressed_ids = {item["id"] for item in suppressed}

    assert kept_ids == {"SEC-1"}
    assert suppressed_ids == {"NGX000-1", "SSH-1"}
    assert any("accepted public dev port" in item["reason"] for item in suppressed)
