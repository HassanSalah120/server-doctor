import json

from server_doctor.engine.finding_fingerprint import (
    fingerprint_finding,
    fingerprint_record,
)
from server_doctor.storage.models import FindingRecord


def test_same_url_with_fragment_produces_same_fingerprint():
    one = fingerprint_finding(
        12,
        "HTTP-PROBE-005",
        "HTTPS://Example.COM/composer.json#top",
        None,
    )
    two = fingerprint_finding(
        12,
        "HTTP-PROBE-005",
        "https://example.com/composer.json",
        None,
    )

    assert one == two


def test_different_paths_produce_different_fingerprints():
    one = fingerprint_finding(12, "HTTP-PROBE-005", "https://e.test/.env", None)
    two = fingerprint_finding(
        12,
        "HTTP-PROBE-005",
        "https://e.test/composer.json",
        None,
    )

    assert one != two


def test_same_rule_on_different_servers_produces_different_fingerprint():
    one = fingerprint_finding(12, "DNS-TLS-005", "example.com", None)
    two = fingerprint_finding(13, "DNS-TLS-005", "example.com", None)

    assert one != two


def test_fingerprint_record_extracts_target_from_evidence_json():
    finding = FindingRecord(
        id=1,
        job_id=1,
        rule_id="HTTP-PROBE-005",
        severity="critical",
        title="Sensitive path exposed",
        evidence_json=json.dumps(
            [{"excerpt": "https://example.com/.env#frag => HTTP 200"}]
        ),
    )

    _fingerprint, target = fingerprint_record(1, finding)

    assert target == "https://example.com/.env"
