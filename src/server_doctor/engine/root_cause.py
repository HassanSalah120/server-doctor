"""Root-cause grouping across stored findings."""

from __future__ import annotations

from dataclasses import asdict, dataclass

from server_doctor.storage.models import FindingRecord


@dataclass
class RootCause:
    id: str
    title: str
    severity: str
    confidence: float
    hypothesis: str
    supporting_rule_ids: list[str]
    evidence_summary: list[str]
    recommended_next_steps: list[str]
    affected_targets: list[str]

    def to_dict(self) -> dict:
        return asdict(self)


def correlate_root_causes(findings: list[FindingRecord]) -> list[RootCause]:
    causes: list[RootCause] = []
    for maybe in (
        correlate_nginx_upstream_down(findings),
        correlate_laravel_queue_redis(findings),
        correlate_ssl_renewal_risk(findings),
        correlate_public_datastore(findings),
        correlate_public_app_files(findings),
        correlate_websocket_failure(findings),
    ):
        if maybe and _not_duplicate(causes, maybe):
            causes.append(maybe)
    return causes


def correlate_nginx_upstream_down(findings: list[FindingRecord]) -> RootCause | None:
    ids = {f.rule_id for f in findings}
    if {"HTTP-PROBE-007", "NODE-RUNTIME-004"} <= ids or {
        "HTTP-PROBE-007",
        "PHPFPM-DEEP-001",
    } <= ids:
        return RootCause(
            id="ROOTCAUSE-UPSTREAM-DOWN",
            title="Application upstream appears down or unreachable",
            severity="critical",
            confidence=0.9,
            hypothesis="Nginx is receiving traffic but cannot reach the backend.",
            supporting_rule_ids=sorted(ids & {
                "HTTP-PROBE-007",
                "NODE-RUNTIME-004",
                "PHPFPM-DEEP-001",
                "PHPFPM-DEEP-003",
                "NODE-RUNTIME-002",
            }),
            evidence_summary=[
                "Live endpoint probe returned gateway error.",
                "Configured upstream target is missing or failed.",
            ],
            recommended_next_steps=[
                "Check the backend service status.",
                "Verify proxy_pass or fastcgi_pass target.",
                "Inspect service logs.",
            ],
            affected_targets=[],
        )
    return None


def correlate_websocket_failure(findings: list[FindingRecord]) -> RootCause | None:
    ids = {f.rule_id for f in findings}
    if "HTTP-PROBE-006" not in ids:
        return None

    support = {"HTTP-PROBE-006"}
    if ids & {"NGX-WSS-001", "NGX-WSS-002", "NGX-WSS-003"}:
        support.update(ids & {"NGX-WSS-001", "NGX-WSS-002", "NGX-WSS-003"})
        cause_class = "nginx_missing_upgrade_headers"
        hypothesis = "Nginx is not forwarding the required WebSocket upgrade headers."
        next_steps = [
            "Set proxy_http_version 1.1 on the WebSocket location.",
            "Forward Upgrade and Connection headers.",
            "Reload Nginx only after nginx -t passes.",
        ]
    elif ids & {"NODE-RUNTIME-004", "ROOTCAUSE-UPSTREAM-DOWN"}:
        support.update(ids & {"NODE-RUNTIME-004", "HTTP-PROBE-007"})
        cause_class = "upstream_port_not_listening"
        hypothesis = "The WebSocket route points to an upstream port that is not listening."
        next_steps = [
            "Start the backend WebSocket service.",
            "Verify proxy_pass host and port.",
            "Check Docker/systemd service logs.",
        ]
    else:
        cause_class = _evidence_cause_class(findings) or "backend_rejected_handshake"
        hypothesis = "The backend did not complete a valid WebSocket upgrade handshake."
        next_steps = [
            "Check application WebSocket route registration.",
            "Verify the backend accepts Upgrade requests on the probed path.",
            "Inspect backend logs for handshake rejection details.",
        ]

    return RootCause(
        id="ROOTCAUSE-WEBSOCKET-FAILURE",
        title=f"WebSocket failure: {cause_class}",
        severity="warning",
        confidence=0.82 if len(support) > 1 else 0.65,
        hypothesis=hypothesis,
        supporting_rule_ids=sorted(support),
        evidence_summary=[
            f.title or f.description or f.rule_id
            for f in findings
            if f.rule_id in support
        ],
        recommended_next_steps=next_steps,
        affected_targets=[
            f.evidence_ref
            for f in findings
            if f.rule_id in support and f.evidence_ref
        ],
    )


def correlate_laravel_queue_redis(findings: list[FindingRecord]) -> RootCause | None:
    ids = {f.rule_id for f in findings}
    if {"LARAVEL-RUNTIME-001", "REDIS-DEEP-008"} <= ids:
        return RootCause(
            id="ROOTCAUSE-LARAVEL-QUEUE-REDIS",
            title="Laravel queue depends on unavailable Redis",
            severity="warning",
            confidence=0.8,
            hypothesis="Queue workers or Redis dependency are preventing async jobs.",
            supporting_rule_ids=sorted(ids & {"LARAVEL-RUNTIME-001", "REDIS-DEEP-008"}),
            evidence_summary=["Laravel queue configuration references Redis."],
            recommended_next_steps=["Start Redis and queue workers.", "Inspect failed jobs."],
            affected_targets=[],
        )
    return None


def correlate_ssl_renewal_risk(findings: list[FindingRecord]) -> RootCause | None:
    ids = {f.rule_id for f in findings}
    if {"DNS-TLS-005", "DNS-TLS-006"} <= ids:
        return RootCause(
            id="ROOTCAUSE-CERT-RENEWAL-RISK",
            title="TLS certificate renewal is at risk",
            severity="critical",
            confidence=0.85,
            hypothesis="The certificate expires soon and renewal automation is unhealthy.",
            supporting_rule_ids=sorted(ids & {"DNS-TLS-005", "DNS-TLS-006", "DNS-TLS-009"}),
            evidence_summary=["Certificate expiry and renewal posture both show risk."],
            recommended_next_steps=["Enable certbot timer.", "Validate challenge path."],
            affected_targets=[],
        )
    return None


def correlate_public_datastore(findings: list[FindingRecord]) -> RootCause | None:
    ids = {f.rule_id for f in findings}
    supported = ids & {"MYSQL-DEEP-001", "REDIS-DEEP-001", "FW-REC-002", "FW-REC-003"}
    if len(supported) >= 2:
        return RootCause(
            id="ROOTCAUSE-PUBLIC-DATASTORE",
            title="Datastore is publicly reachable",
            severity="critical",
            confidence=0.88,
            hypothesis="Database/cache services are reachable beyond trusted networks.",
            supporting_rule_ids=sorted(supported),
            evidence_summary=["Network and datastore checks both indicate public exposure."],
            recommended_next_steps=["Bind services privately.", "Restrict firewall access."],
            affected_targets=[],
        )
    return None


def correlate_public_app_files(findings: list[FindingRecord]) -> RootCause | None:
    ids = {f.rule_id for f in findings}

    has_core = "HTTP-PROBE-005" in ids or "API-005" in ids or "API-001" in ids
    if not has_core:
        return None

    matched: list[FindingRecord] = []
    for f in findings:
        if f.rule_id in ("HTTP-PROBE-005", "API-005", "API-001"):
            continue
        title_matches = f.title and any(
            kw in f.title.lower()
            for kw in ["composer.json", "package.json", "dotfile"]
        )
        if (
            f.rule_id.startswith("NGX-SEC-3")
            or f.rule_id == "LARAVEL-RUNTIME-012"
            or title_matches
        ):
            matched.append(f)

    core_ids = sorted(ids & {"HTTP-PROBE-005", "API-005", "API-001"})
    supporting_ids = sorted({f.rule_id for f in matched}) + core_ids

    evidence_summary = []
    affected_targets = []
    for f in findings:
        if f.rule_id not in supporting_ids:
            continue
        if f.title:
            evidence_summary.append(f.title)
        elif f.description:
            evidence_summary.append(f.description)
        if f.evidence_ref:
            affected_targets.append(f.evidence_ref)

    # Severity = max severity of all supporting findings
    SEV_RANK = {"critical": 3, "warning": 2, "info": 1}
    max_sev = "info"
    for f in findings:
        if f.rule_id not in supporting_ids:
            continue
        sev = (f.severity or "info").lower()
        if SEV_RANK.get(sev, 0) > SEV_RANK.get(max_sev, 0):
            max_sev = sev

    return RootCause(
        id="ROOTCAUSE-PUBLIC-APP-FILES",
        title="Public application files are reachable from the web",
        severity=max_sev,
        confidence=0.9,
        hypothesis=(
            "Web server configuration allows direct access to application source "
            "files and dependency manifests"
        ),
        supporting_rule_ids=supporting_ids,
        evidence_summary=evidence_summary,
        recommended_next_steps=[
            "Block composer.json, package.json, .env, .git, storage/logs, vendor",
            "Ensure app root points to public/build/static output only",
        ],
        affected_targets=affected_targets,
    )


def _not_duplicate(existing: list[RootCause], candidate: RootCause) -> bool:
    candidate_support = set(candidate.supporting_rule_ids)
    return all(set(item.supporting_rule_ids) != candidate_support for item in existing)


def _evidence_cause_class(findings: list[FindingRecord]) -> str | None:
    for finding in findings:
        if finding.rule_id != "HTTP-PROBE-006":
            continue
        text = " ".join(
            str(value or "")
            for value in (finding.title, finding.description, getattr(finding, "evidence_json", None))
        ).lower()
        for cause_class in (
            "nginx_missing_upgrade_headers",
            "upstream_service_missing",
            "upstream_port_not_listening",
            "docker_network_resolution_failed",
            "backend_rejected_handshake",
            "probe_connection_refused",
        ):
            if cause_class in text:
                return cause_class
    return None
