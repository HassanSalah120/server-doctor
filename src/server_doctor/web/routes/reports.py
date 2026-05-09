"""Report and findings API routes.

Endpoints:
    GET /api/reports/{job_id} - Full report (findings + diagnosis + score)
    GET /api/findings         - Query findings (?severity=high&job_id=X)
"""

import json
from datetime import datetime, timezone
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query

from server_doctor import __version__
from server_doctor.engine.drift import ReportCompareResponse, compare_models
from server_doctor.engine.finding_fingerprint import fingerprint_record
from server_doctor.engine.nginx_topology import build_nginx_topology
from server_doctor.engine.regression import regression_metadata
from server_doctor.engine.remediation_classifier import classify_impact
from server_doctor.engine.root_cause import correlate_root_causes
from server_doctor.storage.models import FindingRecord
from server_doctor.storage.repositories import (
    AcceptedRiskRepository,
    FindingRepository,
    LifecycleEventRepository,
    ScanJobRepository,
)
from server_doctor.utils.redaction import redact_value
from server_doctor.web.security import require_auth

router = APIRouter(dependencies=[Depends(require_auth)])
_job_repo = ScanJobRepository()
_finding_repo = FindingRepository()
_lifecycle_repo = LifecycleEventRepository()
_accepted_risk_repo = AcceptedRiskRepository()

SEVERITY_WEIGHT = {
    "critical": 1000,
    "warning": 500,
    "info": 100,
}


def _parse_evidence(value: str | None) -> list[dict[str, Any]]:
    if not value:
        return []
    try:
        parsed = json.loads(value)
    except (json.JSONDecodeError, TypeError):
        return []
    if not isinstance(parsed, list):
        return []
    return [item for item in parsed if isinstance(item, dict)]


def finding_priority(finding: FindingRecord) -> int:
    base = SEVERITY_WEIGHT.get(str(finding.severity).lower(), 0)
    evidence_bonus = 50 if finding.evidence_json else 0
    security_bonus = 100 if str(finding.rule_id).startswith(("SEC", "NGX-SEC", "SSH", "VULN", "DNS-TLS")) else 0
    return base + security_bonus + evidence_bonus


def _finding_view(
    finding: FindingRecord,
    regression_meta: dict[str, Any] | None = None,
) -> dict[str, Any]:
    evidence = _parse_evidence(finding.evidence_json)
    view = {
        "id": finding.id,
        "rule_id": finding.rule_id,
        "severity": finding.severity,
        "title": finding.title,
        "description": finding.description,
        "recommendation": finding.recommendation,
        "impact": None,
        "component": finding.component,
        "affected_target": finding.evidence_ref,
        "fix_priority": finding_priority(finding),
        "evidence": evidence,
        "evidence_warning": "Malformed evidence JSON" if finding.evidence_json and not evidence else None,
        "downtime_impact": classify_impact(finding.rule_id, finding.title or ""),
    }
    view.update(regression_meta or _empty_regression_meta())
    return view


def _empty_regression_meta() -> dict[str, Any]:
    return {
        "is_regression": False,
        "resolved_in_job_id": None,
        "regressed_in_job_id": None,
        "regression_count": 0,
        "first_seen_at": None,
        "last_resolved_at": None,
    }


def _regression_metadata_by_finding(
    server_id: int,
    job_id: int,
    findings: list[FindingRecord],
) -> dict[int, dict[str, Any]]:
    metadata: dict[int, dict[str, Any]] = {}
    for finding in findings:
        fingerprint, _target = fingerprint_record(server_id, finding)
        events = _lifecycle_repo.get_by_fingerprint(server_id, fingerprint)
        accepted = _accepted_risk_repo.is_accepted(
            server_id=server_id,
            rule_id=finding.rule_id,
            finding_title=finding.title,
        )
        metadata[finding.id] = regression_metadata(
            events,
            current_job_id=job_id,
            accepted_active=accepted,
        ).to_dict()
    return metadata


def _safe_str(value: Any, fallback: str = "unknown") -> str:
    text = str(value).strip() if value is not None else ""
    return text if text else fallback


def _shell_quote(value: str) -> str:
    return "'" + value.replace("'", "'\"'\"'") + "'"


def _package_manager_update_command(provider: str) -> str:
    if provider == "apt":
        return "apt list --upgradable 2>/dev/null"
    if provider == "dnf":
        return "dnf -q check-update"
    if provider == "yum":
        return "yum -q check-update"
    return "system package manager update listing"


def _package_manager_head_command(provider: str) -> str:
    if provider == "apt":
        return "apt list --upgradable 2>/dev/null | head -n 20"
    if provider == "dnf":
        return "dnf -q check-update | head -n 20"
    if provider == "yum":
        return "yum -q check-update | head -n 20"
    return "system package manager update listing | head -n 20"


def _expected_exit_text(manager: str, command: str) -> str:
    manager_l = manager.strip().lower()
    command_l = command.strip().lower()
    if manager_l == "npm" and "outdated" in command_l:
        return "Exit 1 means updates are available (successful check). Exit >1 means command/tool failure."
    if manager_l == "npm" and "audit" in command_l:
        return "Exit 1 means vulnerabilities were found (successful audit). Exit >1 means command/tool failure."
    if manager_l == "yarn" and "outdated" in command_l:
        return "Exit 1 means updates are available (successful check). Exit >1 means command/tool failure."
    return "Exit 0 means success. Non-zero usually means command/runtime error for this manager."


def _extract_support_pack(
    job: Any,
    model: dict[str, Any],
    diagnosis: Any,
) -> dict[str, Any]:
    nginx = model.get("nginx") or {}
    os_info = model.get("os") or {}
    supply_chain = model.get("supply_chain") or {}
    security_baseline = model.get("security_baseline") or {}
    vulnerability = model.get("vulnerability") or {}

    os_name = _safe_str(os_info.get("name"), "unknown")
    os_version = _safe_str(os_info.get("version"), "unknown")
    os_codename = str(os_info.get("codename") or "").strip()
    os_text = f"{os_name} {os_version}".strip()
    if os_codename:
        os_text = f"{os_text} ({os_codename})"

    mode = _safe_str(nginx.get("mode"), "unknown").upper()
    provider = _safe_str(security_baseline.get("package_manager"), "unknown").lower()

    install_hint = "host deployment"
    if mode == "DOCKER":
        install_hint = "docker deployment (container-aware nginx scan)"
    elif mode == "HOST":
        install_hint = "host deployment (native nginx scan)"

    runtime_context = {
        "job_id": getattr(job, "id", None),
        "status": _safe_str(getattr(job, "status", None), "unknown"),
        "doctor_version": _safe_str(model.get("doctor_version"), __version__),
        "doctor_build": _safe_str(model.get("commit_hash"), "unknown"),
        "mode": mode,
        "os": os_text,
        "nginx": _safe_str(nginx.get("version"), "unknown"),
        "target_host": _safe_str(model.get("hostname") or getattr(job, "server_host", None), "unknown"),
        "runner": "web job runner",
        "install_hint": install_hint,
        "started_at": getattr(job, "started_at", None),
        "finished_at": getattr(job, "finished_at", None),
        "generated_at": datetime.now(timezone.utc).isoformat(),
    }

    reproduction_commands: list[dict[str, Any]] = []
    evidence_snippets: list[dict[str, Any]] = []
    path_notes: list[str] = []
    seen_commands: set[tuple[str, str]] = set()

    repos = supply_chain.get("repos") or []
    for repo in repos:
        repo_path = _safe_str((repo or {}).get("path"), "")
        if not repo_path:
            continue

        managers = (repo or {}).get("dependency_managers") or []
        if not isinstance(managers, list):
            continue

        nested_dirs: set[str] = set()
        for row in managers:
            if not isinstance(row, dict):
                continue
            detected_files = row.get("detected_files") or []
            for fp in detected_files:
                if not isinstance(fp, str):
                    continue
                parent = fp.rsplit("/", 1)[0] if "/" in fp else fp
                if parent and parent != repo_path and parent.startswith(repo_path.rstrip("/") + "/"):
                    nested_dirs.add(parent)

        if nested_dirs:
            nested_sample = ", ".join(sorted(nested_dirs)[:2])
            if len(nested_dirs) > 2:
                nested_sample += " ..."
            path_notes.append(
                f"{repo_path}: dependency files are in nested paths ({nested_sample}); findings are grouped at repo root."
            )

        for row in managers:
            if not isinstance(row, dict):
                continue
            manager = _safe_str(row.get("manager"), "unknown")
            check_command = str(row.get("check_command") or "").strip()
            audit_command = str(row.get("audit_command") or "").strip()
            status = _safe_str(row.get("status"), "unknown")
            outdated_count = row.get("outdated_count")
            vulnerability_count = row.get("vulnerability_count")
            error_text = str(row.get("error") or "").strip()
            sample = row.get("sample") or []
            vuln_sample = row.get("vulnerability_sample") or []
            vuln_summary = str(row.get("vulnerability_summary") or "").strip()

            observed_bits: list[str] = [f"status={status}"]
            if isinstance(outdated_count, int):
                observed_bits.append(f"outdated={outdated_count}")
            if isinstance(vulnerability_count, int):
                observed_bits.append(f"vulnerabilities={vulnerability_count}")
            if error_text:
                observed_bits.append(f"error={error_text}")

            if check_command:
                key = (repo_path, check_command)
                if key not in seen_commands:
                    seen_commands.add(key)
                    reproduction_commands.append({
                        "title": f"{manager} outdated check",
                        "command": f"cd {_shell_quote(repo_path)} && {check_command}; echo $?",
                        "expected": _expected_exit_text(manager, check_command),
                        "observed": ", ".join(observed_bits),
                    })

            if audit_command:
                key = (repo_path, audit_command)
                if key not in seen_commands:
                    seen_commands.add(key)
                    reproduction_commands.append({
                        "title": f"{manager} vulnerability audit",
                        "command": f"cd {_shell_quote(repo_path)} && {audit_command}; echo $?",
                        "expected": _expected_exit_text(manager, audit_command),
                        "observed": ", ".join(observed_bits),
                    })

            include_snippet = bool(
                (isinstance(outdated_count, int) and outdated_count > 0)
                or (isinstance(vulnerability_count, int) and vulnerability_count > 0)
                or status in {"error", "unsupported", "unavailable"}
            )
            if include_snippet:
                sample_text = ", ".join(str(x) for x in sample[:5]) if sample else "n/a"
                vuln_sample_text = ", ".join(str(x) for x in vuln_sample[:5]) if vuln_sample else "n/a"
                evidence_snippets.append({
                    "topic": f"{repo_path} ({manager})",
                    "command": check_command or audit_command or "dependency check",
                    "snippet": (
                        f"status={status}; outdated={outdated_count if isinstance(outdated_count, int) else 'n/a'}; "
                        f"sample={sample_text}; vulnerabilities={vulnerability_count if isinstance(vulnerability_count, int) else 'n/a'}; "
                        f"summary={vuln_summary or 'n/a'}; vulnerability_sample={vuln_sample_text}"
                    ),
                })

    pending_updates = security_baseline.get("pending_updates_total")
    if isinstance(pending_updates, int) and pending_updates >= 0:
        reproduction_commands.append({
            "title": f"{provider.upper() if provider != 'unknown' else 'OS package manager'} updates",
            "command": _package_manager_update_command(provider),
            "expected": (
                "This is host OS package posture (APT/DNF/YUM), not app dependency managers like npm/pip/composer."
            ),
            "observed": f"pending_updates_total={pending_updates}",
        })

        affected_packages = vulnerability.get("affected_packages") or []
        pkg_sample = ", ".join(str(x) for x in affected_packages[:8]) if affected_packages else "n/a"
        evidence_snippets.append({
            "topic": f"{provider.upper() if provider != 'unknown' else 'OS'} package updates",
            "command": _package_manager_head_command(provider),
            "snippet": f"pending_updates_total={pending_updates}; affected_package_sample={pkg_sample}",
        })

    for note in (supply_chain.get("notes") or [])[:8]:
        note_text = str(note).strip()
        if note_text:
            path_notes.append(note_text)
    for err in (supply_chain.get("errors") or [])[:8]:
        err_text = str(err).strip()
        if err_text:
            path_notes.append(f"scanner_error: {err_text}")

    def _normalize_probe_status(raw: Any) -> str:
        status = str(raw or "").strip().lower()
        if status == "collected":
            return "collected"
        if status in {"not_accessible", "insufficient_permissions", "permission_denied"}:
            return "not_accessible"
        if status in {"unavailable", "not_supported"}:
            return "not_applicable"
        if status in {"timeout", "error"}:
            return "error"
        return "not_observed"

    def _status_maps(section: str) -> tuple[dict[str, str], dict[str, str]]:
        data = model.get(section) or {}
        if not isinstance(data, dict):
            return ({}, {})
        status_map = data.get("collection_status") or {}
        note_map = data.get("collection_notes") or {}
        return (
            status_map if isinstance(status_map, dict) else {},
            note_map if isinstance(note_map, dict) else {},
        )

    logs_status, logs_notes = _status_maps("logs")
    storage_status, storage_notes = _status_maps("storage")
    resources_status, resources_notes = _status_maps("resources")
    kernel_status, kernel_notes = _status_maps("kernel_limits")
    telemetry = model.get("telemetry") or {}

    def _telemetry_has_load() -> bool:
        if not isinstance(telemetry, dict):
            return False
        return any(isinstance(telemetry.get(key), (int, float)) for key in ("load_1", "load_5", "load_15"))

    def _telemetry_has_memory() -> bool:
        if not isinstance(telemetry, dict):
            return False
        return any(isinstance(telemetry.get(key), (int, float)) for key in ("mem_total_mb", "mem_available_mb"))

    def _telemetry_has_disks() -> bool:
        if not isinstance(telemetry, dict):
            return False
        disks = telemetry.get("disks") or []
        return isinstance(disks, list) and len(disks) > 0

    def _coverage_override(label: str, status: str, detail: str) -> tuple[str, str]:
        if label == "journalctl OOM (24h)":
            alt_status = _normalize_probe_status(resources_status.get("resources.journal_oom"))
            if status != "collected" and alt_status == "collected":
                return ("collected", "covered via resources journal OOM probe")
        if label == "host load average" and status != "collected" and _telemetry_has_load():
            return ("collected", "covered via telemetry load probe")
        if label == "host memory info" and status != "collected" and _telemetry_has_memory():
            return ("collected", "covered via telemetry memory probe")
        if label == "disk usage (df -k)" and status != "collected" and _telemetry_has_disks():
            return ("collected", "covered via telemetry disk probe")
        return (status, detail)

    coverage_rows = [
        ("journalctl errors (24h)", "logs", "journal.errors_24h"),
        ("journalctl OOM (24h)", "logs", "journal.oom_24h"),
        ("nginx error logs", "logs", "nginx.error_log"),
        ("php-fpm logs", "logs", "php_fpm.logs"),
        ("docker container status", "logs", "docker.ps"),
        ("docker crashloop logs", "logs", "docker.logs"),
        ("disk usage (df -k)", "storage", "storage.df_disk"),
        ("inode usage (df -i)", "storage", "storage.df_inode"),
        ("mount table (/proc/mounts)", "storage", "storage.proc_mounts"),
        ("mount unit failures (systemd)", "storage", "storage.systemd_failed_mounts"),
        ("iowait (vmstat)", "storage", "storage.vmstat_iowait"),
        ("kernel io errors (dmesg)", "storage", "storage.dmesg_io_errors"),
        ("host load average", "resources", "resources.loadavg"),
        ("host memory info", "resources", "resources.meminfo"),
        ("resource OOM journal", "resources", "resources.journal_oom"),
        ("resource OOM dmesg", "resources", "resources.dmesg_oom"),
        ("top cpu processes", "resources", "resources.ps_cpu"),
        ("top memory processes", "resources", "resources.ps_mem"),
        ("psi cpu (/proc/pressure/cpu)", "resources", "resources.psi_cpu"),
        ("psi memory (/proc/pressure/memory)", "resources", "resources.psi_memory"),
        ("psi io (/proc/pressure/io)", "resources", "resources.psi_io"),
        ("ulimit nofile", "kernel_limits", "kernel.ulimit_nofile"),
        ("sysctl core/net limits", "kernel_limits", "kernel.somaxconn"),
        ("nginx runtime config dump", "kernel_limits", "kernel.nginx_dump"),
    ]

    coverage_matrix: list[dict[str, str]] = []
    for label, section, key in coverage_rows:
        if section == "logs":
            raw_status = logs_status.get(key)
            detail = str(logs_notes.get(key) or "").strip()
        elif section == "storage":
            raw_status = storage_status.get(key)
            detail = str(storage_notes.get(key) or "").strip()
        elif section == "resources":
            raw_status = resources_status.get(key)
            detail = str(resources_notes.get(key) or "").strip()
        else:
            raw_status = kernel_status.get(key)
            detail = str(kernel_notes.get(key) or "").strip()

        status = _normalize_probe_status(raw_status)
        status, detail = _coverage_override(label, status, detail)
        coverage_matrix.append({
            "check": label,
            "status": status,
            "detail": detail[:220],
        })

    expected_behavior = [
        "If host OS updates are pending, label explicitly with package manager scope (for example: APT updates pending).",
        "For `npm outdated`, exit code 1 should be interpreted as success-with-updates, not command failure.",
        "For `npm audit --omit=dev`, exit code 1 should be interpreted as success-with-vulnerabilities, not command failure.",
        "Dependency findings should preserve repo-path context and clearly indicate when checks run in nested subdirectories.",
    ]

    return {
        "runtime_context": runtime_context,
        "raw_diagnosis": diagnosis,
        "reproduction_commands": reproduction_commands[:20],
        "evidence_snippets": evidence_snippets[:20],
        "path_notes": path_notes[:20],
        "coverage_matrix": coverage_matrix,
        "expected_behavior": expected_behavior,
    }


def _extract_ssl_data(model: dict[str, Any]) -> list[dict[str, Any]]:
    """Extract SSL certificate data with countdown info."""
    tls = model.get("tls") or {}
    certs = tls.get("certificates") or []
    result = []
    for cert in certs:
        days = cert.get("days_remaining")
        if days is None:
            status = "unknown"
            color = "gray"
            urgent = False
        elif days <= 7:
            status = "critical"
            color = "red"
            urgent = True
        elif days <= 30:
            status = "warning"
            color = "orange"
            urgent = True
        elif days <= 60:
            status = "caution"
            color = "yellow"
            urgent = False
        else:
            status = "healthy"
            color = "green"
            urgent = False
        result.append({
            "path": cert.get("path", "unknown"),
            "issuer": cert.get("issuer", "unknown"),
            "subject": cert.get("subject", "unknown"),
            "expires_at": cert.get("expires_at", "unknown"),
            "days_remaining": days,
            "sans": cert.get("sans", [])[:8],
            "status": status,
            "color": color,
            "urgent": urgent,
        })
    return result


def _extract_telemetry(model: dict[str, Any]) -> dict[str, Any]:
    """Extract resource metrics from telemetry."""
    telemetry = model.get("telemetry") or {}
    resources = model.get("resources") or {}
    if not telemetry and not resources:
        return {"has_data": False}

    result = {
        "has_data": True,
        "cpu": {
            "cores": None,
            "load_1": None,
            "load_5": None,
            "load_15": None,
            "usage_percent": None,
            "status": "unknown",
        },
        "memory": {},
        "disks": [],
    }

    def _to_float(value: Any) -> float | None:
        if isinstance(value, (int, float)):
            return float(value)
        return None

    # CPU metrics - keep a stable shape even when CPU probing fails.
    cpu_cores_raw = telemetry.get("cpu_cores", resources.get("cpu_cores"))
    cpu_cores = int(cpu_cores_raw) if isinstance(cpu_cores_raw, (int, float)) else None
    load_1 = _to_float(telemetry.get("load_1"))
    load_5 = _to_float(telemetry.get("load_5"))
    load_15 = _to_float(telemetry.get("load_15"))
    if load_1 is None:
        load_1 = _to_float(resources.get("load_1"))
    if load_5 is None:
        load_5 = _to_float(resources.get("load_5"))
    if load_15 is None:
        load_15 = _to_float(resources.get("load_15"))

    result["cpu"]["cores"] = cpu_cores
    result["cpu"]["load_1"] = round(load_1, 2) if load_1 is not None else None
    result["cpu"]["load_5"] = round(load_5, 2) if load_5 is not None else None
    result["cpu"]["load_15"] = round(load_15, 2) if load_15 is not None else None

    if cpu_cores is not None and cpu_cores > 0 and load_1 is not None:
        load_pct = min(100, round((load_1 / cpu_cores) * 100))
        result["cpu"]["usage_percent"] = load_pct
        result["cpu"]["status"] = (
            "critical" if load_pct > 90 else "warning" if load_pct > 70 else "healthy"
        )

    # Memory metrics - be more lenient for Docker containers
    mem_total = telemetry.get("mem_total_mb")
    if not isinstance(mem_total, (int, float)):
        mem_total = resources.get("mem_total_mb")

    mem_available = telemetry.get("mem_available_mb")
    if mem_available is None:
        mem_available = resources.get("mem_available_mb")
    if mem_total:
        if mem_available is not None:
            used_mb = mem_total - mem_available
            used_pct = round((used_mb / mem_total) * 100)
            result["memory"] = {
                "total_gb": round(mem_total / 1024, 2),
                "available_gb": round(mem_available / 1024, 2),
                "used_gb": round(used_mb / 1024, 2),
                "used_percent": used_pct,
                "status": "critical" if used_pct > 90 else "warning" if used_pct > 80 else "healthy",
            }
        else:
            # No available data - just show total
            result["memory"] = {
                "total_gb": round(mem_total / 1024, 2),
                "available_gb": None,
                "used_gb": None,
                "used_percent": None,
                "status": "unknown",
            }
    
    # Disk metrics
    disks = telemetry.get("disks") or []
    filtered_disks: list[dict[str, Any]] = []
    seen_mounts: set[str] = set()
    for disk in sorted(disks, key=lambda d: d.get("used_percent", 0), reverse=True):
        mount = str(disk.get("mount", "") or "")
        if not mount or mount in seen_mounts:
            continue
        # Hide noisy per-container overlay mounts to keep the card actionable.
        if mount.startswith("/var/lib/docker/overlay2/") and mount.endswith("/merged"):
            continue
        seen_mounts.add(mount)
        filtered_disks.append(disk)

    for disk in filtered_disks[:4]:
        used_pct = disk.get("used_percent", 0)
        result["disks"].append({
            "mount": disk.get("mount", "unknown"),
            "total_gb": disk.get("total_gb", 0),
            "used_gb": disk.get("used_gb", 0),
            "used_percent": used_pct,
            "status": "critical" if used_pct > 90 else "warning" if used_pct > 80 else "healthy",
        })
    
    return result


def _extract_topology(model: dict[str, Any]) -> dict[str, Any]:
    """Extract Nginx → Apps → DBs topology."""
    nginx = model.get("nginx") or {}
    services = model.get("services") or {}
    runtime = model.get("runtime") or {}
    php = model.get("php") or {}
    
    # Build app nodes from upstreams
    apps: list[dict[str, Any]] = []
    upstreams = sorted(
        nginx.get("upstreams") or [],
        key=lambda u: str((u or {}).get("name", "")),
    )
    for upstream in upstreams:
        app_name = upstream.get("name", "unknown")
        servers = sorted(upstream.get("servers") or [])
        # Parse server addresses
        targets = []
        for server in servers:
            # Extract host:port from proxy URLs
            addr = server
            if "//" in server:
                addr = server.split("//")[1].split("/")[0]
            targets.append(addr)
        apps.append({
            "name": app_name,
            "type": "upstream",
            "targets": targets,
        })
    
    # Add Docker containers as apps (primary source: services.docker_containers)
    containers = sorted(
        services.get("docker_containers")
        or (runtime.get("docker") or {}).get("containers")
        or [],
        key=lambda c: str((c or {}).get("name", "")),
    )
    for container in containers:
        deduped_ports: list[int] = []
        seen_ports: set[int] = set()
        for mapping in (container.get("ports") or []):
            host_port = mapping.get("host_port")
            if not isinstance(host_port, int):
                continue
            if host_port in seen_ports:
                continue
            seen_ports.add(host_port)
            deduped_ports.append(host_port)

        apps.append({
            "name": container.get("name", "unknown"),
            "type": "docker",
            "image": container.get("image", "unknown"),
            "status": container.get("status") or container.get("state", "unknown"),
            "ports": deduped_ports,
        })

    # Add systemd services
    systemd_services = sorted(
        runtime.get("systemd_services") or [],
        key=lambda s: str((s or {}).get("name", "")),
    )
    for svc in systemd_services[:10]:  # Limit to 10
        sub_state = svc.get("substate") or svc.get("sub_state")
        if sub_state == "running":
            apps.append({
                "name": svc.get("name", "unknown"),
                "type": "systemd",
                "status": sub_state,
                "ports": svc.get("ports", []),
            })
    
    # Add php-fpm if detected
    php_sockets = php.get("sockets") or []
    php_versions = php.get("versions") or []
    if php_sockets or php_versions:
        apps.append({
            "name": "php-fpm",
            "type": "php-fpm",
            "status": "running" if php_sockets else "unknown",
            "versions": php_versions,
            "sockets": php_sockets,
        })
    
    # Detect databases from services
    dbs: list[dict[str, Any]] = []
    
    # MySQL/MariaDB
    for key in ("mysql", "mariadb"):
        svc = services.get(key)
        if svc and svc.get("state") in ("active", "running"):
            dbs.append({
                "type": "mysql" if key == "mysql" else "mariadb",
                "version": svc.get("version", "unknown"),
                "status": svc.get("state", "unknown"),
            })
    
    # PostgreSQL
    postgres = services.get("postgresql") or services.get("postgres")
    if postgres and postgres.get("state") in ("active", "running"):
        dbs.append({
            "type": "postgresql",
            "version": postgres.get("version", "unknown"),
            "status": postgres.get("state", "unknown"),
        })
    
    # MongoDB
    mongo = services.get("mongodb") or services.get("mongo")
    if mongo and mongo.get("state") in ("active", "running"):
        dbs.append({
            "type": "mongodb",
            "version": mongo.get("version", "unknown"),
            "status": mongo.get("state", "unknown"),
        })
    
    # Redis
    redis = services.get("redis")
    if redis and redis.get("state") in ("active", "running"):
        dbs.append({
            "type": "redis",
            "version": redis.get("version", "unknown"),
            "status": redis.get("state", "unknown"),
        })
    
    # Elasticsearch
    es = services.get("elasticsearch")
    if es and es.get("state") in ("active", "running"):
        dbs.append({
            "type": "elasticsearch",
            "version": es.get("version", "unknown"),
            "status": es.get("state", "unknown"),
        })
    
    # Extract network endpoints
    network_surface = model.get("network_surface") or {}
    endpoints = network_surface.get("endpoints") or []
    network_summary: list[dict[str, Any]] = []
    seen_endpoints: set[tuple[str, str, int]] = set()
    for ep in endpoints:
        protocol = ep.get("protocol", "tcp")
        address = ep.get("address", "unknown")
        port = ep.get("port", 0)
        if not isinstance(port, int):
            continue
        key = (str(protocol), str(address), port)
        if key in seen_endpoints:
            continue
        seen_endpoints.add(key)
        network_summary.append({
            "address": address,
            "port": port,
            "protocol": protocol,
        })
    network_summary = sorted(
        network_summary,
        key=lambda e: (int(e.get("port", 0) or 0), str(e.get("address", "")), str(e.get("protocol", ""))),
    )[:10]

    apps = sorted(
        apps,
        key=lambda a: (str(a.get("type", "")), str(a.get("name", ""))),
    )
    
    # Extract certbot status
    certbot = model.get("certbot") or {}
    certbot_status: dict[str, Any] | None = None
    if certbot.get("installed"):
        certbot_status = {
            "installed": True,
            "service_failed": certbot.get("service_failed", False),
            "domains": certbot.get("domains", []),
            "expiry_days": certbot.get("expiry_days", []),
        }
    
    return {
        "has_data": len(apps) > 0 or len(dbs) > 0 or len(network_summary) > 0,
        "nginx": {
            "version": nginx.get("version", "unknown"),
            "mode": nginx.get("mode", "unknown"),
            "server_count": len(nginx.get("servers", [])),
        },
        "apps": apps[:15],  # Limit
        "databases": dbs,
        "network": network_summary,
        "certbot": certbot_status,
    }


def _extract_port_map(model: dict[str, Any]) -> list[dict[str, Any]]:
    """Extract port mappings for visualization."""
    ports: list[dict[str, Any]] = []
    seen_ports: set[int] = set()
    
    # From nginx config directly
    nginx = model.get("nginx") or {}
    for server in nginx.get("servers", []):
        for listen in server.get("listen", []):
            # Parse port from listen directive (e.g., "443 ssl" -> 443)
            port_str = listen.split()[0] if listen else ""
            try:
                port = int(port_str)
                if port and port not in seen_ports:
                    seen_ports.add(port)
                    ports.append({
                        "port": port,
                        "service": "nginx",
                        "type": "tcp",
                        "status": "open",
                    })
            except (ValueError, TypeError):
                pass
    
    # From services.nginx if available
    services = model.get("services") or {}
    nginx_svc = services.get("nginx")
    if nginx_svc:
        for port in nginx_svc.get("listening_ports") or []:
            if port not in seen_ports:
                seen_ports.add(port)
                ports.append({
                    "port": port,
                    "service": "nginx",
                    "type": "tcp",
                    "status": "open",
                })
    
    # From runtime processes
    runtime = model.get("runtime") or {}
    processes = runtime.get("processes") or []
    for proc in processes[:20]:
        for port in proc.get("listening_ports") or []:
            if port not in seen_ports:
                seen_ports.add(port)
                ports.append({
                    "port": port,
                    "service": proc.get("name", "unknown"),
                    "type": "tcp",
                    "status": "open",
                })
    
    # From Docker containers (in services, not runtime)
    docker_containers = services.get("docker_containers") or []
    for container in docker_containers:
        for port_mapping in container.get("ports") or []:
            host_port = port_mapping.get("host_port")
            if host_port and host_port not in seen_ports:
                seen_ports.add(host_port)
                ports.append({
                    "port": host_port,
                    "service": f"docker:{container.get('name', 'unknown')}",
                    "container_port": port_mapping.get("container_port"),
                    "type": "docker",
                    "status": "open",
                })
    
    return sorted(ports, key=lambda p: p["port"])[:30]  # Limit to 30 ports


def _extract_service_health(model: dict[str, Any]) -> list[dict[str, Any]]:
    """Extract service health timeline data."""
    health: list[dict[str, Any]] = []
    
    runtime = model.get("runtime") or {}
    systemd_services = sorted(
        runtime.get("systemd_services") or [],
        key=lambda s: str((s or {}).get("name", "")),
    )
    for svc in systemd_services[:10]:
        # Runtime model uses "substate"; keep "sub_state" as fallback for older payloads.
        sub_state = svc.get("substate") or svc.get("sub_state") or "unknown"
        state = svc.get("state", "unknown")
        norm_sub = str(sub_state).lower()
        norm_state = str(state).lower()
        # systemd one-shot units commonly end up "exited" and create noise.
        if norm_sub == "exited" and norm_state in {"active", "inactive"}:
            continue
        ports = svc.get("ports") or []
        health.append({
            "name": svc.get("name", "unknown"),
            "state": state,
            "sub_state": sub_state,
            "restart_count": svc.get("restart_count", 0) or 0,
            "health": "healthy" if norm_sub in {"running", "listening"} else "unhealthy",
            "ports": ports if isinstance(ports, list) else [],
        })
    
    # Docker containers (in services.docker_containers, not runtime.docker)
    services = model.get("services") or {}
    docker_containers = sorted(
        services.get("docker_containers") or [],
        key=lambda c: str((c or {}).get("name", "")),
    )
    for container in docker_containers[:10]:
        # Docker scanner stores runtime in "status"; keep "state" fallback for compatibility.
        state = container.get("status") or container.get("state") or "unknown"
        health.append({
            "name": container.get("name", "unknown"),
            "state": state,
            "restart_count": container.get("restart_count", 0) or 0,
            "health": "healthy" if state == "running" else "unhealthy",
            "ports": [],
            "type": "docker",
        })
    
    return sorted(
        health,
        key=lambda item: (
            str(item.get("type", "systemd")),
            str(item.get("name", "")),
        ),
    )


def _extract_logs(model: dict[str, Any]) -> dict[str, Any]:
    """Extract log-derived incident signals."""
    logs = model.get("logs") or {}
    resources = model.get("resources") or {}
    if not isinstance(logs, dict) or not logs:
        logs = {}
        if not isinstance(resources, dict) or not resources:
            return {"has_data": False}

    def _as_int(value: Any) -> int | None:
        return int(value) if isinstance(value, (int, float)) else None

    nginx_counts_raw = logs.get("nginx_error_counts") or {}
    nginx_counts: dict[str, int] = {}
    if isinstance(nginx_counts_raw, dict):
        for key, value in nginx_counts_raw.items():
            if isinstance(key, str) and isinstance(value, (int, float)) and int(value) > 0:
                nginx_counts[key] = int(value)

    php_counts_raw = logs.get("php_fpm_error_counts") or {}
    php_counts: dict[str, int] = {}
    if isinstance(php_counts_raw, dict):
        for key, value in php_counts_raw.items():
            if isinstance(key, str) and isinstance(value, (int, float)) and int(value) > 0:
                php_counts[key] = int(value)

    nginx_samples = [str(line) for line in (logs.get("nginx_error_samples") or []) if str(line).strip()][:8]
    php_samples = [str(line) for line in (logs.get("php_fpm_error_samples") or []) if str(line).strip()][:8]
    docker_crashloops = [str(name) for name in (logs.get("docker_crashloop_containers") or []) if str(name).strip()][:10]
    docker_samples = [str(line) for line in (logs.get("docker_error_samples") or []) if str(line).strip()][:8]
    collection_status = {
        str(key): str(value)
        for key, value in ((logs.get("collection_status") or {}).items() if isinstance(logs.get("collection_status"), dict) else [])
        if str(key).strip()
    }
    collection_notes = {
        str(key): str(value)
        for key, value in ((logs.get("collection_notes") or {}).items() if isinstance(logs.get("collection_notes"), dict) else [])
        if str(key).strip() and str(value).strip()
    }

    journal_errors = _as_int(logs.get("journal_errors_24h"))
    journal_oom = _as_int(logs.get("journal_oom_events_24h"))
    if journal_oom is None:
        journal_oom = _as_int(resources.get("oom_events_24h"))
    nginx_total = sum(nginx_counts.values())

    has_data = any([
        journal_errors is not None,
        journal_oom is not None,
        bool(nginx_counts),
        bool(php_counts),
        bool(nginx_samples),
        bool(php_samples),
        bool(docker_crashloops),
        bool(docker_samples),
    ])
    if not has_data:
        return {"has_data": False}

    status = "healthy"
    if (
        (journal_oom is not None and journal_oom >= 3)
        or len(docker_crashloops) >= 2
        or nginx_total >= 20
    ):
        status = "critical"
    elif (
        (journal_errors is not None and journal_errors >= 120)
        or (journal_oom is not None and journal_oom > 0)
        or bool(docker_crashloops)
        or nginx_total >= 5
        or bool(php_counts)
    ):
        status = "warning"

    return {
        "has_data": True,
        "status": status,
        "journal_errors_24h": journal_errors,
        "journal_oom_events_24h": journal_oom,
        "nginx_error_counts": nginx_counts,
        "nginx_error_samples": nginx_samples,
        "php_fpm_error_counts": php_counts,
        "php_fpm_error_samples": php_samples,
        "docker_crashloop_containers": docker_crashloops,
        "docker_error_samples": docker_samples,
        "collection_status": collection_status,
        "collection_notes": collection_notes,
    }


def _extract_storage(model: dict[str, Any]) -> dict[str, Any]:
    """Extract storage health data."""
    storage = model.get("storage") or {}
    if not isinstance(storage, dict) or not storage:
        return {"has_data": False}

    def _as_float(value: Any) -> float | None:
        if isinstance(value, (int, float)):
            return float(value)
        return None

    mounts: list[dict[str, Any]] = []
    for mount in storage.get("mounts") or []:
        if not isinstance(mount, dict):
            continue
        name = str(mount.get("mount") or "").strip()
        if not name:
            continue
        used_percent = _as_float(mount.get("used_percent")) or 0.0
        inode_used = _as_float(mount.get("inode_used_percent"))
        mount_status = "healthy"
        if used_percent >= 97 or (inode_used is not None and inode_used >= 97):
            mount_status = "critical"
        elif used_percent >= 92 or (inode_used is not None and inode_used >= 92):
            mount_status = "warning"

        mounts.append({
            "mount": name,
            "total_gb": round((_as_float(mount.get("total_gb")) or 0.0), 2),
            "used_gb": round((_as_float(mount.get("used_gb")) or 0.0), 2),
            "used_percent": round(used_percent, 1),
            "inode_used_percent": round(inode_used, 1) if inode_used is not None else None,
            "read_only": bool(mount.get("read_only")),
            "status": mount_status,
        })

    mounts = sorted(mounts, key=lambda m: float(m.get("used_percent", 0.0)), reverse=True)
    if not mounts:
        telemetry = model.get("telemetry") or {}
        for disk in telemetry.get("disks") or []:
            if not isinstance(disk, dict):
                continue
            name = str(disk.get("mount") or "").strip()
            if not name:
                continue
            if name.startswith("/var/lib/docker/overlay2/") and name.endswith("/merged"):
                continue
            used_percent = _as_float(disk.get("used_percent")) or 0.0
            mount_status = "healthy"
            if used_percent >= 97:
                mount_status = "critical"
            elif used_percent >= 92:
                mount_status = "warning"
            mounts.append({
                "mount": name,
                "total_gb": round((_as_float(disk.get("total_gb")) or 0.0), 2),
                "used_gb": round((_as_float(disk.get("used_gb")) or 0.0), 2),
                "used_percent": round(used_percent, 1),
                "inode_used_percent": None,
                "read_only": False,
                "status": mount_status,
            })
        mounts = sorted(mounts, key=lambda m: float(m.get("used_percent", 0.0)), reverse=True)
    read_only_mounts = [str(m) for m in (storage.get("read_only_mounts") or []) if str(m).strip()][:20]
    failed_mount_units = [str(m) for m in (storage.get("failed_mount_units") or []) if str(m).strip()][:20]
    io_wait = _as_float(storage.get("io_wait_percent"))
    io_errors = [str(line) for line in (storage.get("io_error_samples") or []) if str(line).strip()][:8]
    collection_status = {
        str(key): str(value)
        for key, value in ((storage.get("collection_status") or {}).items() if isinstance(storage.get("collection_status"), dict) else [])
        if str(key).strip()
    }
    collection_notes = {
        str(key): str(value)
        for key, value in ((storage.get("collection_notes") or {}).items() if isinstance(storage.get("collection_notes"), dict) else [])
        if str(key).strip() and str(value).strip()
    }

    has_data = bool(mounts or read_only_mounts or failed_mount_units or io_wait is not None or io_errors)
    if not has_data:
        return {"has_data": False}

    status = "healthy"
    max_mount = max((float(m.get("used_percent", 0.0)) for m in mounts), default=0.0)
    if max_mount >= 97 or (io_wait is not None and io_wait >= 40) or bool(io_errors):
        status = "critical"
    elif max_mount >= 92 or (io_wait is not None and io_wait >= 20) or bool(failed_mount_units):
        status = "warning"

    return {
        "has_data": True,
        "status": status,
        "mounts": mounts[:10],
        "read_only_mounts": read_only_mounts,
        "failed_mount_units": failed_mount_units,
        "io_wait_percent": round(io_wait, 1) if io_wait is not None else None,
        "io_error_samples": io_errors,
        "collection_status": collection_status,
        "collection_notes": collection_notes,
    }


def _extract_resources(model: dict[str, Any]) -> dict[str, Any]:
    """Extract resource pressure/oom/process hotspot data."""
    resources = model.get("resources") or {}
    telemetry = model.get("telemetry") or {}
    if not isinstance(resources, dict) or not resources:
        resources = {}
        if not isinstance(telemetry, dict) or not telemetry:
            return {"has_data": False}

    def _as_int(value: Any) -> int | None:
        return int(value) if isinstance(value, (int, float)) else None

    def _as_float(value: Any) -> float | None:
        if isinstance(value, (int, float)):
            return float(value)
        return None

    cpu_cores = _as_int(resources.get("cpu_cores"))
    if cpu_cores is None:
        cpu_cores = _as_int(telemetry.get("cpu_cores"))
    load_1 = _as_float(resources.get("load_1"))
    if load_1 is None:
        load_1 = _as_float(telemetry.get("load_1"))
    load_5 = _as_float(resources.get("load_5"))
    if load_5 is None:
        load_5 = _as_float(telemetry.get("load_5"))
    load_15 = _as_float(resources.get("load_15"))
    if load_15 is None:
        load_15 = _as_float(telemetry.get("load_15"))
    mem_total_mb = _as_int(resources.get("mem_total_mb"))
    if mem_total_mb is None:
        mem_total_mb = _as_int(telemetry.get("mem_total_mb"))
    mem_available_mb = _as_int(resources.get("mem_available_mb"))
    if mem_available_mb is None:
        mem_available_mb = _as_int(telemetry.get("mem_available_mb"))
    swap_total_mb = _as_int(resources.get("swap_total_mb"))
    if swap_total_mb is None:
        swap_total_mb = _as_int(telemetry.get("swap_total_mb"))
    swap_free_mb = _as_int(resources.get("swap_free_mb"))
    if swap_free_mb is None:
        swap_free_mb = _as_int(telemetry.get("swap_free_mb"))
    oom_events = _as_int(resources.get("oom_events_24h"))
    psi_cpu = _as_float(resources.get("psi_cpu_some_avg10"))
    psi_mem = _as_float(resources.get("psi_memory_some_avg10"))
    psi_io = _as_float(resources.get("psi_io_some_avg10"))

    mem_used_mb = None
    mem_used_percent = None
    if mem_total_mb is not None and mem_available_mb is not None and mem_total_mb > 0:
        mem_used_mb = max(0, mem_total_mb - mem_available_mb)
        mem_used_percent = round((mem_used_mb / mem_total_mb) * 100)

    swap_used_mb = None
    swap_used_percent = None
    if swap_total_mb is not None and swap_free_mb is not None and swap_total_mb > 0:
        swap_used_mb = max(0, swap_total_mb - swap_free_mb)
        swap_used_percent = round((swap_used_mb / swap_total_mb) * 100)

    load_percent = None
    if cpu_cores is not None and cpu_cores > 0 and load_1 is not None:
        load_percent = min(100, round((load_1 / cpu_cores) * 100))

    top_cpu = [str(line) for line in (resources.get("top_cpu_processes") or []) if str(line).strip()][:6]
    top_mem = [str(line) for line in (resources.get("top_mem_processes") or []) if str(line).strip()][:6]
    collection_status = {
        str(key): str(value)
        for key, value in ((resources.get("collection_status") or {}).items() if isinstance(resources.get("collection_status"), dict) else [])
        if str(key).strip()
    }
    collection_notes = {
        str(key): str(value)
        for key, value in ((resources.get("collection_notes") or {}).items() if isinstance(resources.get("collection_notes"), dict) else [])
        if str(key).strip() and str(value).strip()
    }

    has_data = any([
        cpu_cores is not None,
        load_1 is not None,
        mem_total_mb is not None,
        swap_total_mb is not None,
        oom_events is not None,
        psi_cpu is not None,
        psi_mem is not None,
        psi_io is not None,
        bool(top_cpu),
        bool(top_mem),
    ])
    if not has_data:
        return {"has_data": False}

    status = "healthy"
    if (
        (oom_events is not None and oom_events >= 3)
        or (psi_mem is not None and psi_mem >= 6)
        or (psi_io is not None and psi_io >= 6)
    ):
        status = "critical"
    elif (
        (oom_events is not None and oom_events > 0)
        or (load_percent is not None and load_percent >= 80)
        or (mem_used_percent is not None and mem_used_percent >= 85)
        or (psi_mem is not None and psi_mem >= 2)
        or (psi_io is not None and psi_io >= 2)
        or (psi_cpu is not None and psi_cpu >= 20)
    ):
        status = "warning"

    return {
        "has_data": True,
        "status": status,
        "cpu_cores": cpu_cores,
        "load_1": round(load_1, 2) if load_1 is not None else None,
        "load_5": round(load_5, 2) if load_5 is not None else None,
        "load_15": round(load_15, 2) if load_15 is not None else None,
        "load_percent": load_percent,
        "mem_total_mb": mem_total_mb,
        "mem_available_mb": mem_available_mb,
        "mem_used_mb": mem_used_mb,
        "mem_used_percent": mem_used_percent,
        "swap_total_mb": swap_total_mb,
        "swap_free_mb": swap_free_mb,
        "swap_used_mb": swap_used_mb,
        "swap_used_percent": swap_used_percent,
        "oom_events_24h": oom_events,
        "psi_cpu_some_avg10": round(psi_cpu, 2) if psi_cpu is not None else None,
        "psi_memory_some_avg10": round(psi_mem, 2) if psi_mem is not None else None,
        "psi_io_some_avg10": round(psi_io, 2) if psi_io is not None else None,
        "top_cpu_processes": top_cpu,
        "top_mem_processes": top_mem,
        "collection_status": collection_status,
        "collection_notes": collection_notes,
    }


def _extract_kernel_limits(model: dict[str, Any]) -> dict[str, Any]:
    """Extract kernel/system limit posture."""
    limits = model.get("kernel_limits") or {}
    if not isinstance(limits, dict) or not limits:
        return {"has_data": False}

    def _as_int(value: Any) -> int | None:
        return int(value) if isinstance(value, (int, float)) else None

    nofile_soft = _as_int(limits.get("nofile_soft"))
    nofile_hard = _as_int(limits.get("nofile_hard"))
    fs_file_max = _as_int(limits.get("fs_file_max"))
    somaxconn = _as_int(limits.get("somaxconn"))
    syn_backlog = _as_int(limits.get("tcp_max_syn_backlog"))
    port_start = _as_int(limits.get("ip_local_port_range_start"))
    port_end = _as_int(limits.get("ip_local_port_range_end"))
    fin_timeout = _as_int(limits.get("tcp_fin_timeout"))
    netdev_backlog = _as_int(limits.get("netdev_max_backlog"))
    worker_connections = _as_int(limits.get("nginx_worker_connections"))
    worker_processes = _as_int(limits.get("nginx_worker_processes"))
    collection_status = {
        str(key): str(value)
        for key, value in ((limits.get("collection_status") or {}).items() if isinstance(limits.get("collection_status"), dict) else [])
        if str(key).strip()
    }
    collection_notes = {
        str(key): str(value)
        for key, value in ((limits.get("collection_notes") or {}).items() if isinstance(limits.get("collection_notes"), dict) else [])
        if str(key).strip() and str(value).strip()
    }

    has_data = any([
        nofile_soft is not None,
        nofile_hard is not None,
        fs_file_max is not None,
        somaxconn is not None,
        syn_backlog is not None,
        port_start is not None,
        port_end is not None,
        fin_timeout is not None,
        netdev_backlog is not None,
        worker_connections is not None,
        worker_processes is not None,
    ])
    if not has_data:
        return {"has_data": False}

    port_range_width = None
    if port_start is not None and port_end is not None and port_end > port_start:
        port_range_width = port_end - port_start

    worker_fd_budget = None
    if worker_connections is not None and worker_processes is not None:
        worker_fd_budget = worker_connections * worker_processes

    status = "healthy"
    if (
        (nofile_soft is not None and nofile_soft < 8192)
        or (worker_connections is not None and nofile_soft is not None and worker_connections > nofile_soft)
    ):
        status = "critical"
    elif (
        (nofile_soft is not None and nofile_soft < 32768)
        or (somaxconn is not None and somaxconn < 1024)
        or (syn_backlog is not None and syn_backlog < 2048)
        or (port_range_width is not None and port_range_width < 20000)
    ):
        status = "warning"

    # Data quality guard: avoid "healthy" when collection had probe errors.
    error_states = {"error", "timeout", "insufficient_permissions"}
    probe_errors = [
        value for value in collection_status.values()
        if str(value).strip().lower() in error_states
    ]
    if status == "healthy" and probe_errors:
        status = "warning"

    return {
        "has_data": True,
        "status": status,
        "nofile_soft": nofile_soft,
        "nofile_hard": nofile_hard,
        "fs_file_max": fs_file_max,
        "somaxconn": somaxconn,
        "tcp_max_syn_backlog": syn_backlog,
        "ip_local_port_range_start": port_start,
        "ip_local_port_range_end": port_end,
        "ip_local_port_range_width": port_range_width,
        "tcp_fin_timeout": fin_timeout,
        "netdev_max_backlog": netdev_backlog,
        "nginx_worker_connections": worker_connections,
        "nginx_worker_processes": worker_processes,
        "nginx_worker_fd_budget": worker_fd_budget,
        "collection_status": collection_status,
        "collection_notes": collection_notes,
    }


@router.get("/reports/{job_id}")
async def get_report(job_id: int) -> dict:
    """Get full report for a completed scan job.

    Includes findings, score, AI diagnosis, SSL status, and telemetry.
    """
    job = _job_repo.get_by_id(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")

    if job.status not in ("success", "failed"):
        return {
            "job": job.to_dict(),
            "findings": [],
            "diagnosis": None,
            "ssl_status": [],
            "telemetry": {"has_data": False},
            "logs": {"has_data": False},
            "storage": {"has_data": False},
            "resources": {"has_data": False},
            "kernel_limits": {"has_data": False},
            "support_pack": {
                "runtime_context": {
                    "job_id": job.id,
                    "status": job.status,
                    "doctor_version": __version__,
                    "doctor_build": "unknown",
                    "mode": "unknown",
                    "os": "unknown",
                    "nginx": "unknown",
                    "target_host": getattr(job, "server_host", None) or "unknown",
                    "runner": "web job runner",
                    "install_hint": "unknown",
                    "started_at": job.started_at,
                    "finished_at": job.finished_at,
                    "generated_at": datetime.now(timezone.utc).isoformat(),
                },
                "raw_diagnosis": None,
                "reproduction_commands": [],
                "evidence_snippets": [],
                "path_notes": [],
                "coverage_matrix": [],
                "expected_behavior": [],
            },
            "message": f"Job is still {job.status}",
        }

    findings = _finding_repo.get_by_job_id(job_id)
    regression_meta = _regression_metadata_by_finding(
        job.server_id,
        job_id,
        findings,
    )
    finding_views = sorted(
        (_finding_view(f, regression_meta.get(f.id)) for f in findings),
        key=lambda f: int(f.get("fix_priority", 0)),
        reverse=True,
    )
    root_causes = [item.to_dict() for item in correlate_root_causes(findings)]

    # Parse diagnosis JSON if available
    diagnosis = None
    if job.diagnosis_json:
        try:
            diagnosis = json.loads(job.diagnosis_json)
        except (json.JSONDecodeError, TypeError):
            pass

    # Parse model JSON for SSL and telemetry
    ssl_status: list[dict[str, Any]] = []
    telemetry: dict[str, Any] = {"has_data": False}
    topology: dict[str, Any] = {"has_data": False}
    port_map: list[dict[str, Any]] = []
    service_health: list[dict[str, Any]] = []
    logs: dict[str, Any] = {"has_data": False}
    storage: dict[str, Any] = {"has_data": False}
    resources: dict[str, Any] = {"has_data": False}
    kernel_limits: dict[str, Any] = {"has_data": False}
    nginx_topology: list[dict[str, Any]] = []
    support_pack: dict[str, Any] = {
        "runtime_context": {
            "job_id": job.id,
            "status": job.status,
            "doctor_version": __version__,
            "doctor_build": "unknown",
            "mode": "unknown",
            "os": "unknown",
            "nginx": "unknown",
            "target_host": getattr(job, "server_host", None) or "unknown",
            "runner": "web job runner",
            "install_hint": "unknown",
            "started_at": job.started_at,
            "finished_at": job.finished_at,
            "generated_at": datetime.now(timezone.utc).isoformat(),
        },
        "raw_diagnosis": diagnosis,
        "reproduction_commands": [],
        "evidence_snippets": [],
        "path_notes": [],
        "coverage_matrix": [],
        "expected_behavior": [],
    }
    
    if job.model_json:
        try:
            model = json.loads(job.model_json)
            ssl_status = _extract_ssl_data(model)
            telemetry = _extract_telemetry(model)
            topology = _extract_topology(model)
            port_map = _extract_port_map(model)
            service_health = _extract_service_health(model)
            logs = _extract_logs(model)
            storage = _extract_storage(model)
            resources = _extract_resources(model)
            kernel_limits = _extract_kernel_limits(model)
            nginx_topology = [node.model_dump() for node in build_nginx_topology(model)]
            support_pack = _extract_support_pack(job, model, diagnosis)
        except (json.JSONDecodeError, TypeError):
            pass

    return {
        "job": job.to_dict(),
        "findings": [
            {**f.to_dict(), **regression_meta.get(f.id, _empty_regression_meta())}
            for f in findings
        ],
        "normalized_findings": finding_views,
        "diagnosis": diagnosis,
        "ssl_status": ssl_status,
        "telemetry": telemetry,
        "logs": logs,
        "storage": storage,
        "resources": resources,
        "kernel_limits": kernel_limits,
        "topology": topology,
        "port_map": port_map,
        "service_health": service_health,
        "support_pack": redact_value(support_pack),
        "nginx_topology": nginx_topology,
        "root_causes": root_causes,
    }


@router.get("/reports/{job_id}/compare", response_model=ReportCompareResponse)
async def compare_report(job_id: int) -> ReportCompareResponse:
    job = _job_repo.get_by_id(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")

    jobs = [candidate for candidate in _job_repo.get_by_server_id(job.server_id, limit=10) if candidate.id != job_id]
    previous = jobs[0] if jobs else None
    if not previous:
        return ReportCompareResponse(
            current_job_id=job_id,
            previous_job_id=None,
            score_delta=None,
            new_findings=[],
            resolved_findings=[],
            drift=[],
        )

    def _load_model(raw: str | None) -> dict[str, Any]:
        if not raw:
            return {}
        try:
            parsed = json.loads(raw)
        except (TypeError, json.JSONDecodeError):
            return {}
        return parsed if isinstance(parsed, dict) else {}

    current_ids = {f.rule_id for f in _finding_repo.get_by_job_id(job_id)}
    previous_ids = {f.rule_id for f in _finding_repo.get_by_job_id(previous.id)}
    score_delta = None
    if job.score is not None and previous.score is not None:
        score_delta = job.score - previous.score

    return ReportCompareResponse(
        current_job_id=job_id,
        previous_job_id=previous.id,
        score_delta=score_delta,
        new_findings=sorted(current_ids - previous_ids),
        resolved_findings=sorted(previous_ids - current_ids),
        drift=compare_models(_load_model(previous.model_json), _load_model(job.model_json)),
    )


@router.get("/findings")
async def query_findings(
    severity: str | None = Query(None, description="Filter by severity"),
    job_id: int | None = Query(None, description="Filter by job ID"),
) -> dict:
    """Query findings with optional filters."""
    if severity and job_id:
        findings = _finding_repo.get_by_severity(severity, job_id=job_id)
    elif severity:
        findings = _finding_repo.get_by_severity(severity)
    elif job_id:
        findings = _finding_repo.get_by_job_id(job_id)
    else:
        # Return recent findings (last 100)
        from server_doctor.storage.db import get_db

        db = get_db()
        rows = db.execute(
            "SELECT * FROM findings ORDER BY created_at DESC LIMIT 100"
        ).fetchall()
        findings = [
            FindingRepository._row_to_record(row)  # type: ignore[arg-type]
            for row in rows
        ]

    return {"findings": [f.to_dict() for f in findings]}
