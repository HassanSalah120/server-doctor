from server_doctor.engine.root_cause import correlate_root_causes
from server_doctor.storage.models import FindingRecord


def _finding(rule_id):
    return FindingRecord(
        id=1,
        job_id=1,
        rule_id=rule_id,
        severity="critical",
        title=rule_id,
    )


def test_http_502_dead_proxy_creates_upstream_root_cause():
    causes = correlate_root_causes([
        _finding("HTTP-PROBE-007"),
        _finding("NODE-RUNTIME-004"),
    ])

    assert causes[0].id == "ROOTCAUSE-UPSTREAM-DOWN"


def test_unrelated_missing_header_creates_no_root_cause():
    assert correlate_root_causes([_finding("NGX-SEC-1")]) == []


def test_duplicate_findings_produce_one_root_cause():
    causes = correlate_root_causes([
        _finding("HTTP-PROBE-007"),
        _finding("NODE-RUNTIME-004"),
        _finding("NODE-RUNTIME-004"),
    ])

    assert len(causes) == 1


def test_websocket_probe_and_missing_upgrade_headers_create_root_cause():
    causes = correlate_root_causes([
        _finding("HTTP-PROBE-006"),
        _finding("NGX-WSS-002"),
    ])

    ws = next(c for c in causes if c.id == "ROOTCAUSE-WEBSOCKET-FAILURE")
    assert "nginx_missing_upgrade_headers" in ws.title
    assert ws.supporting_rule_ids == ["HTTP-PROBE-006", "NGX-WSS-002"]


def test_websocket_probe_alone_is_lower_confidence_root_cause():
    causes = correlate_root_causes([_finding("HTTP-PROBE-006")])

    assert causes[0].id == "ROOTCAUSE-WEBSOCKET-FAILURE"
    assert causes[0].confidence < 0.7
