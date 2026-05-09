"""Safe, preview-only fix plan generation."""

from __future__ import annotations

import json
import re

from pydantic import BaseModel

from server_doctor.storage.models import FindingRecord


class FixCommand(BaseModel):
    label: str
    command: str
    requires_sudo: bool = False


class FixPlan(BaseModel):
    finding_id: int
    rule_id: str
    can_auto_fix: bool
    risk: str
    summary: str
    files_affected: list[str]
    backup_commands: list[FixCommand]
    apply_commands: list[FixCommand]
    validate_commands: list[FixCommand]
    rollback_commands: list[FixCommand]
    warnings: list[str]


def build_fix_plan(finding: FindingRecord) -> FixPlan:
    rule_id = finding.rule_id or "unknown"
    base_rule_id = _base_rule_id(rule_id)

    if base_rule_id in {"DNS-TLS-002", "DNS-TLS-012"}:
        return _no_action_plan(
            finding,
            risk="low",
            summary="No remediation is required; this finding is informational.",
            warning="Keep monitoring this signal during future scans.",
        )

    if base_rule_id in {"HTTP-PROBE-005", "HTTP-PROBE-SOFT404"}:
        url = _extract_url(finding)
        sensitive_path = _path_from_url(url) or _extract_path(finding) or "/sensitive-path"
        is_soft_404 = base_rule_id == "HTTP-PROBE-SOFT404"
        return _nginx_plan(
            finding,
            risk="medium" if is_soft_404 else "high",
            summary=(
                "Return 404 for sensitive fake paths before the SPA fallback."
                if is_soft_404
                else (
                    "Block the exposed sensitive path in Nginx and validate it returns "
                    "403 or 404."
                )
            ),
            apply=[
                FixCommand(
                    label="Add deny rule for sensitive path",
                    command=(
                        "sudoedit "
                        f"{_shell_quote(_affected_nginx_file(finding))} "
                        f"# add: location = {sensitive_path} {{ deny all; return 404; }}"
                    ),
                    requires_sudo=True,
                )
            ],
            validate=[
                FixCommand(
                    label="Validate sensitive path is blocked",
                    command=_curl_status_command(url)
                    if url
                    else f"curl -Ik https://<domain>{sensitive_path}",
                )
            ],
            warnings=[
                (
                    "This is likely a soft-404, not confirmed file exposure; fix routing "
                    "so scanners and users get a real 404."
                    if is_soft_404
                    else (
                        "Do not delete application files as a first step; block public "
                        "web access in Nginx."
                    )
                ),
                "Validation should observe HTTP 403 or 404, not 200/206/301/302.",
            ],
        )

    if base_rule_id in {"API-001", "NGX-SENS-1"}:
        path = _extract_path(finding) or "/admin"
        return _nginx_plan(
            finding,
            risk="medium",
            summary="Restrict the sensitive route with authentication or an IP allowlist.",
            apply=[
                FixCommand(
                    label="Protect sensitive route",
                    command=(
                        "sudoedit "
                        f"{_shell_quote(_affected_nginx_file(finding))} "
                        f"# add auth_basic or allow/deny controls for {path}"
                    ),
                    requires_sudo=True,
                )
            ],
            validate=[
                FixCommand(
                    label="Validate route is not public",
                    command=f"curl -Ik https://<domain>{path}",
                )
            ],
            warnings=[
                "Prefer authentication for admin/API routes; IP allowlists are only safe "
                "when operator IP ranges are stable.",
            ],
        )

    if base_rule_id == "HTTP-PROBE-004":
        url = _extract_url(finding)
        return _nginx_plan(
            finding,
            risk="medium",
            summary="Add a port 80 redirect to the canonical HTTPS URL.",
            apply=[
                FixCommand(
                    label="Add HTTP to HTTPS redirect",
                    command=(
                        "sudoedit "
                        f"{_shell_quote(_affected_nginx_file(finding))} "
                        "# add: return 301 https://$host$request_uri; in the listen 80 server"
                    ),
                    requires_sudo=True,
                )
            ],
            validate=[
                FixCommand(
                    label="Validate redirect",
                    command=_curl_headers_command(url) if url else "curl -I http://<domain>",
                )
            ],
            warnings=["Confirm the HTTPS virtual host works before redirecting all HTTP traffic."],
        )

    if base_rule_id == "HTTP-PROBE-006":
        ws_path = _path_from_url(_extract_url(finding)) or _extract_path(finding) or "/ws"
        return _nginx_plan(
            finding,
            risk="medium",
            summary="Review WebSocket proxy headers and upstream listener for the failing route.",
            apply=[
                FixCommand(
                    label="Add WebSocket proxy headers",
                    command=(
                        "sudoedit "
                        f"{_shell_quote(_affected_nginx_file(finding))} "
                        f"# ensure {ws_path} sets proxy_http_version 1.1, Upgrade, and Connection"
                    ),
                    requires_sudo=True,
                )
            ],
            validate=[
                FixCommand(
                    label="Validate WebSocket handshake",
                    command=(
                        "curl -ik --http1.1 -H 'Connection: Upgrade' "
                        "-H 'Upgrade: websocket' https://<domain>"
                        f"{ws_path}"
                    ),
                )
            ],
            warnings=[
                "If headers are already present, validate the upstream service and Docker/network "
                "target instead of editing Nginx.",
            ],
        )

    if base_rule_id in {"HTTP-PROBE-001", "HTTP-PROBE-007"}:
        url = _extract_url(finding)
        return FixPlan(
            finding_id=finding.id,
            rule_id=rule_id,
            can_auto_fix=False,
            risk="high",
            summary="Fix the failed upstream/application service, then re-probe the endpoint.",
            files_affected=[],
            backup_commands=[],
            apply_commands=[
                FixCommand(
                    label="Inspect failed services",
                    command="systemctl --failed --no-pager",
                ),
                FixCommand(
                    label="Inspect listening ports",
                    command="ss -ltnp",
                ),
            ],
            validate_commands=[
                FixCommand(
                    label="Validate endpoint is no longer 5xx",
                    command=_curl_status_command(url) if url else "curl -Ik https://<domain>",
                )
            ],
            rollback_commands=[],
            warnings=[
                "This plan is diagnostic because upstream fixes depend on the owning service.",
            ],
        )

    if base_rule_id == "DNS-TLS-005":
        return FixPlan(
            finding_id=finding.id,
            rule_id=rule_id,
            can_auto_fix=False,
            risk="high" if finding.severity == "critical" else "medium",
            summary=(
                "Renew or repair the certificate before expiry, then verify the served "
                "certificate."
            ),
            files_affected=["/etc/letsencrypt"],
            backup_commands=[
                FixCommand(
                    label="Backup Let's Encrypt state",
                    command=(
                        "sudo tar -czf /etc/letsencrypt.serverdoctor.bak.tgz "
                        "/etc/letsencrypt"
                    ),
                    requires_sudo=True,
                )
            ],
            apply_commands=[
                FixCommand(
                    label="Run Certbot dry-run",
                    command="sudo certbot renew --dry-run",
                    requires_sudo=True,
                ),
                FixCommand(
                    label="Renew certificate if dry-run is clean",
                    command="sudo certbot renew",
                    requires_sudo=True,
                ),
            ],
            validate_commands=[
                FixCommand(
                    label="Validate served certificate dates",
                    command=(
                        "echo | openssl s_client -servername <domain> -connect <domain>:443 "
                        "2>/dev/null | openssl x509 -noout -dates -subject -issuer"
                    ),
                )
            ],
            rollback_commands=[
                FixCommand(
                    label="Restore Let's Encrypt backup",
                    command=(
                        "sudo tar -xzf /etc/letsencrypt.serverdoctor.bak.tgz -C / "
                        "&& sudo systemctl reload nginx"
                    ),
                    requires_sudo=True,
                )
            ],
            warnings=[
                "Run renewal only after dry-run succeeds; investigate ACME challenge "
                "failures first.",
            ],
        )

    if base_rule_id in {"HOST-002", "HOST-004"}:
        setting = (
            "PasswordAuthentication no"
            if base_rule_id == "HOST-002"
            else "AllowTcpForwarding no"
        )
        return FixPlan(
            finding_id=finding.id,
            rule_id=rule_id,
            can_auto_fix=False,
            risk="medium",
            summary=f"Review SSH hardening and set `{setting}` if it matches server policy.",
            files_affected=["/etc/ssh/sshd_config", "/etc/ssh/sshd_config.d"],
            backup_commands=[
                FixCommand(
                    label="Backup SSH config",
                    command="sudo cp -a /etc/ssh /etc/ssh.serverdoctor.bak",
                    requires_sudo=True,
                )
            ],
            apply_commands=[
                FixCommand(
                    label="Edit SSH daemon config",
                    command=f"sudoedit /etc/ssh/sshd_config # set: {setting}",
                    requires_sudo=True,
                )
            ],
            validate_commands=[
                FixCommand(
                    label="Validate SSH config",
                    command="sudo sshd -t",
                    requires_sudo=True,
                )
            ],
            rollback_commands=[
                FixCommand(
                    label="Restore SSH config backup",
                    command="sudo cp -a /etc/ssh.serverdoctor.bak /etc/ssh",
                    requires_sudo=True,
                )
            ],
            warnings=[
                "Keep an existing SSH session open and verify key-based access before "
                "reloading sshd.",
            ],
        )

    if base_rule_id == "NGX-DEEP-008":
        return _nginx_plan(
            finding,
            risk="medium",
            summary="Align the location path and proxy_pass trailing slash semantics.",
            apply=[
                FixCommand(
                    label="Edit proxy_pass slash handling",
                    command=(
                        "sudoedit "
                        f"{_shell_quote(_affected_nginx_file(finding))} "
                        "# make location and proxy_pass trailing slashes intentional"
                    ),
                    requires_sudo=True,
                )
            ],
            validate=[
                FixCommand(
                    label="Validate proxied route",
                    command="curl -Ik https://<domain>/<affected-path>",
                )
            ],
            warnings=[
                "Changing proxy_pass slash behavior can rewrite upstream paths; test "
                "affected routes.",
            ],
        )

    if base_rule_id.startswith("NGX-SEC") or base_rule_id.startswith("NGX008"):
        return _nginx_plan(
            finding,
            risk="medium",
            summary="Nginx security/header/default-site finding requires manual config review.",
            apply=[
                FixCommand(
                    label="Edit Nginx config",
                    command=f"sudoedit {_shell_quote(_affected_nginx_file(finding))}",
                    requires_sudo=True,
                )
            ],
            validate=[],
            warnings=["Manual config diff required before apply."],
        )

    if base_rule_id.startswith("SC-DEP"):
        return FixPlan(
            finding_id=finding.id,
            rule_id=rule_id,
            can_auto_fix=False,
            risk="medium",
            summary=(
                "Review dependency updates in the affected repository and validate "
                "tests/build."
            ),
            files_affected=[finding.evidence_ref] if finding.evidence_ref else [],
            backup_commands=[
                FixCommand(
                    label="Record current dependency manifests",
                    command=(
                        "git status --short && git diff -- package.json "
                        "package-lock.json composer.json composer.lock"
                    ),
                )
            ],
            apply_commands=[
                FixCommand(
                    label="Review dependency update plan",
                    command="npm audit fix --dry-run || composer audit",
                )
            ],
            validate_commands=[
                FixCommand(
                    label="Validate application build/tests",
                    command="npm test && npm run build",
                )
            ],
            rollback_commands=[
                FixCommand(
                    label="Revert dependency manifest changes",
                    command=(
                        "git restore package.json package-lock.json composer.json "
                        "composer.lock"
                    ),
                )
            ],
            warnings=[
                "Run dependency changes in the app repository, not on production blindly.",
                "Use the package manager that matches the affected project.",
            ],
        )

    if base_rule_id.startswith("LOG"):
        return FixPlan(
            finding_id=finding.id,
            rule_id=rule_id,
            can_auto_fix=False,
            risk="medium",
            summary=(
                "Inspect recent logs, fix the owning app/service, then verify the error "
                "stops recurring."
            ),
            files_affected=[finding.evidence_ref] if finding.evidence_ref else [],
            backup_commands=[],
            apply_commands=[
                FixCommand(
                    label="Inspect Nginx errors",
                    command="sudo tail -n 100 /var/log/nginx/error.log",
                    requires_sudo=True,
                ),
                FixCommand(
                    label="Inspect failed units",
                    command="systemctl --failed --no-pager",
                ),
            ],
            validate_commands=[
                FixCommand(
                    label="Validate recent error rate",
                    command="sudo tail -n 100 /var/log/nginx/error.log",
                    requires_sudo=True,
                )
            ],
            rollback_commands=[],
            warnings=[
                "Log findings usually require app-specific remediation before validation "
                "passes."
            ],
        )

    return FixPlan(
        finding_id=finding.id,
        rule_id=rule_id,
        can_auto_fix=False,
        risk="unknown",
        summary="No safe automatic fix is registered for this rule.",
        files_affected=[],
        backup_commands=[],
        apply_commands=[],
        validate_commands=[],
        rollback_commands=[],
        warnings=["No automatic fix available."],
    )


def _nginx_plan(
    finding: FindingRecord,
    *,
    risk: str,
    summary: str,
    apply: list[FixCommand],
    validate: list[FixCommand],
    warnings: list[str],
) -> FixPlan:
    nginx_file = _affected_nginx_file(finding)
    return FixPlan(
        finding_id=finding.id,
        rule_id=finding.rule_id,
        can_auto_fix=False,
        risk=risk,
        summary=summary,
        files_affected=[nginx_file],
        backup_commands=[
            FixCommand(
                label="Backup Nginx config",
                command="sudo cp -a /etc/nginx /etc/nginx.serverdoctor.bak",
                requires_sudo=True,
            )
        ],
        apply_commands=apply,
        validate_commands=[
            FixCommand(
                label="Validate Nginx config",
                command="sudo nginx -t",
                requires_sudo=True,
            ),
            *validate,
        ],
        rollback_commands=[
            FixCommand(
                label="Restore Nginx backup",
                command="sudo cp -a /etc/nginx.serverdoctor.bak /etc/nginx",
                requires_sudo=True,
            ),
            FixCommand(
                label="Validate restored Nginx config",
                command="sudo nginx -t",
                requires_sudo=True,
            ),
        ],
        warnings=warnings,
    )


def _no_action_plan(
    finding: FindingRecord,
    *,
    risk: str,
    summary: str,
    warning: str,
) -> FixPlan:
    return FixPlan(
        finding_id=finding.id,
        rule_id=finding.rule_id,
        can_auto_fix=False,
        risk=risk,
        summary=summary,
        files_affected=[],
        backup_commands=[],
        apply_commands=[],
        validate_commands=[],
        rollback_commands=[],
        warnings=[warning],
    )


def _base_rule_id(rule_id: str) -> str:
    return re.sub(r"\.\d+$", "", rule_id or "unknown")


def _affected_nginx_file(finding: FindingRecord) -> str:
    ref = finding.evidence_ref
    if ref and ref.startswith("/"):
        return ref
    for value in _evidence_values(finding):
        if value.startswith("/etc/nginx"):
            return value.split(":", 1)[0]
    return "/etc/nginx"


def _extract_url(finding: FindingRecord) -> str | None:
    for value in _all_text_values(finding):
        match = re.search(r"https?://[^\s;,)]+", value)
        if match:
            return match.group(0).rstrip(".")
    return None


def _extract_path(finding: FindingRecord) -> str | None:
    for value in _all_text_values(finding):
        match = re.search(r"(/[A-Za-z0-9._~!$&'()*+,;=:@%/-]+)", value)
        if match:
            path = match.group(1)
            if path.startswith("//"):
                continue
            return path
    return None


def _path_from_url(url: str | None) -> str | None:
    if not url:
        return None
    match = re.match(r"https?://[^/]+(?P<path>/[^?#]*)", url)
    if not match:
        return None
    return match.group("path") or "/"


def _all_text_values(finding: FindingRecord) -> list[str]:
    values = [
        finding.title or "",
        finding.description or "",
        finding.evidence_ref or "",
        finding.recommendation or "",
        *_evidence_values(finding),
    ]
    return [value for value in values if value]


def _evidence_values(finding: FindingRecord) -> list[str]:
    if not finding.evidence_json:
        return []
    try:
        parsed = json.loads(finding.evidence_json)
    except (json.JSONDecodeError, TypeError):
        return []
    if not isinstance(parsed, list):
        return []
    values: list[str] = []
    for item in parsed:
        if not isinstance(item, dict):
            continue
        for key in ("source_file", "excerpt", "command"):
            value = item.get(key)
            if isinstance(value, str):
                values.append(value)
    return values


def _curl_status_command(url: str | None) -> str:
    if not url:
        return "curl -sk -o /dev/null -w '%{http_code}' --max-time 8 https://<domain>"
    return f"curl -sk -o /dev/null -w '%{{http_code}}' --max-time 8 {_shell_quote(url)}"


def _curl_headers_command(url: str | None) -> str:
    if not url:
        return "curl -I -L --max-redirs 5 http://<domain>"
    return f"curl -I -L --max-redirs 5 {_shell_quote(url)}"


def _shell_quote(value: str) -> str:
    return "'" + value.replace("'", "'\"'\"'") + "'"
