from server_doctor.engine.readiness import build_readiness
from server_doctor.storage.models import FindingRecord


def _finding(rule_id, severity="critical"):
    return FindingRecord(
        id=1,
        job_id=1,
        rule_id=rule_id,
        severity=severity,
        title=rule_id,
    )


def test_blocker_rule_makes_ready_false():
    readiness = build_readiness(1, [_finding("HTTP-PROBE-007")])

    assert readiness.ready is False
    assert readiness.blockers


def test_only_info_findings_keeps_ready_true():
    readiness = build_readiness(1, [_finding("DNS-TLS-002", "info")])

    assert readiness.ready is True
