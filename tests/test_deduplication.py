from server_doctor.engine.deduplication import deduplicate_findings
from server_doctor.model.evidence import Evidence, Severity
from server_doctor.model.finding import Finding


def _finding(fid: str, condition: str) -> Finding:
    return Finding(
        id=fid,
        severity=Severity.WARNING,
        confidence=0.9,
        condition=condition,
        cause="cause",
        treatment="fix",
        impact=["impact"],
        evidence=[Evidence(source_file="x", line_number=1, excerpt="e")],
    )


def test_preserves_explicit_numeric_ids() -> None:
    findings = [
        _finding("CERTBOT-4", "Certbot unused but failed"),
        _finding("SYSTEMD-1", "Service failed"),
    ]

    deduped = deduplicate_findings(findings)
    ids = {f.id for f in deduped}
    assert "CERTBOT-4" in ids
    assert "SYSTEMD-1" in ids


def test_numbers_unsuffixed_ids() -> None:
    findings = [
        _finding("NGX002", "Duplicate server_name a"),
        _finding("NGX002", "Duplicate server_name b"),
    ]

    deduped = deduplicate_findings(findings)
    ids = [f.id for f in deduped]
    assert "NGX002-1" in ids
    assert "NGX002-2" in ids


def test_differentiates_repeated_explicit_ids() -> None:
    findings = [
        _finding("SEC-HEAD-1", "Missing in /health"),
        _finding("SEC-HEAD-1", "Missing in /api"),
    ]

    deduped = deduplicate_findings(findings)
    ids = [f.id for f in deduped]
    assert "SEC-HEAD-1" in ids
    assert "SEC-HEAD-1.2" in ids


def test_keeps_dotted_explicit_ids_without_extra_suffix() -> None:
    findings = [
        _finding("DOCKER-3", "Port 3000 proxied"),
        _finding("DOCKER-3", "Port 8104 proxied"),
    ]
    deduped = deduplicate_findings(findings)
    ids = {f.id for f in deduped}
    assert "DOCKER-3" in ids
    assert "DOCKER-3.2" in ids


def test_suffix_assignment_is_stable_across_input_order() -> None:
    a = [
        _finding("NGX002", "Duplicate server_name A"),
        _finding("NGX002", "Duplicate server_name B"),
        _finding("SEC-HEAD-1", "Missing in /api"),
        _finding("SEC-HEAD-1", "Missing in /health"),
    ]
    b = list(reversed(a))

    dedup_a = deduplicate_findings(a)
    dedup_b = deduplicate_findings(b)

    map_a = {f.condition: f.id for f in dedup_a}
    map_b = {f.condition: f.id for f in dedup_b}
    assert map_a == map_b
