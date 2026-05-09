from pathlib import Path

from server_doctor.engine.history import ScanHistoryStore
from server_doctor.model.evidence import Evidence, Severity
from server_doctor.model.finding import Finding


def _finding(fid: str, condition: str) -> Finding:
    return Finding(
        id=fid,
        severity=Severity.WARNING,
        confidence=0.8,
        condition=condition,
        cause="cause",
        evidence=[Evidence(source_file="x", line_number=1, excerpt="e")],
        treatment="t",
        impact=["i"],
    )


def test_history_trend_new_and_resolved(tmp_path: Path):
    store = ScanHistoryStore(base_dir=tmp_path)
    host = "example.host"

    first = [_finding("NGX-1", "A"), _finding("SEC-1", "B")]
    trend_first = store.compute_trend(host, first, current_score=70, timestamp="2026-02-11T10:00:00")
    assert trend_first["has_previous"] is False
    store.append_scan(host, first, score=70, timestamp="2026-02-11T10:00:00")

    second = [_finding("SEC-1", "B"), _finding("SSH-1", "C")]
    trend_second = store.compute_trend(host, second, current_score=80, timestamp="2026-02-11T11:00:00")

    assert trend_second["has_previous"] is True
    assert trend_second["score_delta"] == 10
    assert {item["id"] for item in trend_second["new_findings"]} == {"SSH-1"}
    assert {item["id"] for item in trend_second["resolved_findings"]} == {"NGX-1"}


def test_history_trend_topology_diff(tmp_path: Path):
    store = ScanHistoryStore(base_dir=tmp_path)
    host = "example.host"

    findings = [_finding("NGX-1", "A")]
    topo1 = {
        "signature": "s1",
        "route_keys": ["a|/|x|proxy"],
        "binding_keys": ["c|0.0.0.0|3000|3000|tcp"],
        "stats": {"routes": 1, "public_bindings": 1},
    }
    topo2 = {
        "signature": "s2",
        "route_keys": ["a|/|x|proxy", "a|/api|y|proxy"],
        "binding_keys": ["c|0.0.0.0|3000|3000|tcp"],
        "stats": {"routes": 2, "public_bindings": 1},
    }

    store.append_scan(host, findings, score=70, timestamp="2026-02-11T10:00:00", topology=topo1)
    trend = store.compute_trend(
        host,
        findings,
        current_score=70,
        timestamp="2026-02-11T11:00:00",
        current_topology=topo2,
    )

    assert trend["topology_diff"] is not None
    assert trend["topology_diff"]["has_previous"] is True
    assert trend["topology_diff"]["signature_changed"] is True
    assert trend["topology_diff"]["added_routes"] == ["a|/api|y|proxy"]
