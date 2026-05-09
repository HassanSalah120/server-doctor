"""Fix Center API routes."""

import base64
from datetime import datetime
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from server_doctor.connector.ssh import SSHConfig, SSHConnector
from server_doctor.engine.finding_fingerprint import fingerprint_record
from server_doctor.engine.fix_plan import FixPlan, build_fix_plan
from server_doctor.engine.fix_validation import (
    ValidationResult,
    build_validation_plan,
    evaluate_validation,
)
from server_doctor.engine.nginx_sensitive_path_apply import (
    build_sensitive_path_apply_plan,
    build_sensitive_path_patch,
    sensitive_path_validation_command,
    validate_sensitive_path_status,
)
from server_doctor.storage.repositories import (
    FindingRepository,
    FixAttemptRepository,
    LifecycleEventRepository,
    ScanJobRepository,
    ServerRepository,
)
from server_doctor.web.secrets import get_server_key_passphrase, get_server_password
from server_doctor.web.security import require_auth, require_csrf

router = APIRouter(prefix="/fixes", tags=["fixes"], dependencies=[Depends(require_auth)])


class FixPreviewResponse(BaseModel):
    job_id: int
    plans: list[FixPlan]


class ConfirmFixRequest(BaseModel):
    finding_ids: list[int]
    confirmation: str
    ack_backup: bool
    ack_risk: bool


class ValidateFindingRequest(BaseModel):
    finding_id: int
    mode: str = "preview"
    one_time_password: str | None = None
    one_time_key_passphrase: str | None = None


class ValidateFindingResponse(BaseModel):
    finding_id: int
    rule_id: str
    can_validate: bool
    command: str | None
    expected: str
    status: str
    observed: str | None = None
    error: str | None = None
    attempt_id: int | None = None


class SafeApplySensitivePathRequest(BaseModel):
    finding_id: int
    mode: Literal["preview", "apply"] = "preview"
    confirmation: str | None = None
    ack_backup: bool = False
    ack_risk: bool = False
    one_time_password: str | None = None
    one_time_key_passphrase: str | None = None


class SafeApplySensitivePathResponse(BaseModel):
    finding_id: int
    rule_id: str
    mode: str
    can_apply: bool
    status: str
    expected: str
    nginx_file: str | None = None
    target_url: str | None = None
    patch_preview: str | None = None
    backup_path: str | None = None
    observed: str | None = None
    error: str | None = None
    rollback_performed: bool = False
    attempt_id: int | None = None


@router.post("/preview", response_model=FixPreviewResponse)
async def preview_fixes(job_id: int) -> FixPreviewResponse:
    job = ScanJobRepository().get_by_id(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")
    findings = FindingRepository().get_by_job_id(job_id)
    return FixPreviewResponse(
        job_id=job_id,
        plans=[build_fix_plan(finding) for finding in findings],
    )


@router.post(
    "/validate",
    response_model=ValidateFindingResponse,
    dependencies=[Depends(require_csrf)],
)
async def validate_finding(request: ValidateFindingRequest) -> ValidateFindingResponse:
    if request.mode not in {"preview", "run"}:
        raise HTTPException(status_code=400, detail="mode must be preview or run")

    finding = FindingRepository().get_by_id(request.finding_id)
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")
    job = ScanJobRepository().get_by_id(finding.job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")
    server = ServerRepository().get_by_id(job.server_id)
    if not server:
        raise HTTPException(status_code=404, detail="Server not found")

    plan = build_validation_plan(finding)
    if request.mode == "preview" or not plan.can_validate:
        return ValidateFindingResponse(
            finding_id=finding.id,
            rule_id=finding.rule_id,
            can_validate=plan.can_validate,
            command=plan.command,
            expected=plan.expected,
            status="preview" if plan.can_validate else "not_validatable",
        )

    password = (
        request.one_time_password
        or get_server_password(server.password_secret_ref)
        or server.password
    )
    passphrase = (
        request.one_time_key_passphrase
        or get_server_key_passphrase(server.key_passphrase_secret_ref)
    )
    config = SSHConfig(
        host=server.host,
        user=server.username,
        port=server.port,
        key_path=server.key_path,
        passphrase=passphrase,
        password=password,
        use_sudo=True,
    )

    try:
        with SSHConnector(config) as ssh:
            result = ssh.run(plan.command)
        validation = evaluate_validation(
            finding,
            stdout=result.stdout,
            stderr=result.stderr,
            exit_code=result.exit_code,
        )
    except Exception as exc:
        validation = ValidationResult(
            finding_id=finding.id,
            rule_id=finding.rule_id,
            status="error",
            command=plan.command,
            expected=plan.expected,
            observed=None,
            error=str(exc),
        )

    attempt_id = FixAttemptRepository().create(
        finding_id=finding.id,
        job_id=finding.job_id,
        server_id=job.server_id,
        rule_id=finding.rule_id,
        action="validate",
        status=validation.status,
        command=validation.command,
        expected=validation.expected,
        observed=validation.observed,
        error=validation.error,
    )
    if validation.status in {"resolved", "still_failing", "error"}:
        fingerprint, target = fingerprint_record(job.server_id, finding)
        LifecycleEventRepository().create(
            server_id=job.server_id,
            job_id=finding.job_id,
            finding_fingerprint=fingerprint,
            rule_id=finding.rule_id,
            target=target,
            event_type=(
                "validated_resolved"
                if validation.status == "resolved"
                else "validation_failed"
            ),
            source="fix_validation",
            details={
                "fix_attempt_id": attempt_id,
                "expected": validation.expected,
                "observed": validation.observed,
                "status": validation.status,
                "error": validation.error,
            },
        )
    return ValidateFindingResponse(
        finding_id=finding.id,
        rule_id=finding.rule_id,
        can_validate=plan.can_validate,
        command=validation.command,
        expected=validation.expected,
        status=validation.status,
        observed=validation.observed,
        error=validation.error,
        attempt_id=attempt_id,
    )


@router.post(
    "/safe-apply/sensitive-path",
    response_model=SafeApplySensitivePathResponse,
    dependencies=[Depends(require_csrf)],
)
async def safe_apply_sensitive_path(
    request: SafeApplySensitivePathRequest,
) -> SafeApplySensitivePathResponse:
    """Preview/apply SAFE-APPLY-001 for Nginx sensitive fake/static paths."""
    finding = FindingRepository().get_by_id(request.finding_id)
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")
    job = ScanJobRepository().get_by_id(finding.job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")
    server = ServerRepository().get_by_id(job.server_id)
    if not server:
        raise HTTPException(status_code=404, detail="Server not found")

    plan = build_sensitive_path_apply_plan(finding, job)
    if not plan.can_apply:
        return SafeApplySensitivePathResponse(
            finding_id=finding.id,
            rule_id=finding.rule_id,
            mode=request.mode,
            can_apply=False,
            status="not_applicable",
            expected=plan.expected,
            nginx_file=plan.nginx_file,
            target_url=plan.target_url,
            error=plan.reason,
        )

    password = (
        request.one_time_password
        or get_server_password(server.password_secret_ref)
        or server.password
    )
    passphrase = (
        request.one_time_key_passphrase
        or get_server_key_passphrase(server.key_passphrase_secret_ref)
    )
    config = SSHConfig(
        host=server.host,
        user=server.username,
        port=server.port,
        key_path=server.key_path,
        passphrase=passphrase,
        password=password,
        use_sudo=True,
    )

    try:
        with SSHConnector(config) as ssh:
            content = ssh.read_file(plan.nginx_file)
            if content is None:
                raise RuntimeError(f"Unable to read {plan.nginx_file}")
            modified, patch_preview = build_sensitive_path_patch(content, plan)
            if modified is None:
                return SafeApplySensitivePathResponse(
                    finding_id=finding.id,
                    rule_id=finding.rule_id,
                    mode=request.mode,
                    can_apply=False,
                    status="not_applicable",
                    expected=plan.expected,
                    nginx_file=plan.nginx_file,
                    target_url=plan.target_url,
                    error=patch_preview,
                )
            if request.mode == "preview":
                return SafeApplySensitivePathResponse(
                    finding_id=finding.id,
                    rule_id=finding.rule_id,
                    mode="preview",
                    can_apply=True,
                    status="preview",
                    expected=plan.expected,
                    nginx_file=plan.nginx_file,
                    target_url=plan.target_url,
                    patch_preview=patch_preview,
                )

            _validate_sensitive_apply_confirmation(request)
            result = _run_sensitive_path_apply(
                ssh=ssh,
                finding=finding,
                job_id=finding.job_id,
                server_id=job.server_id,
                nginx_file=plan.nginx_file,
                target_url=plan.target_url,
                modified_content=modified,
                patch_preview=patch_preview,
                expected=plan.expected,
            )
    except HTTPException:
        raise
    except Exception as exc:
        return _record_safe_apply_failure(
            finding=finding,
            server_id=job.server_id,
            expected=plan.expected,
            error=str(exc),
            nginx_file=plan.nginx_file,
            target_url=plan.target_url,
        )

    return result


def _validate_sensitive_apply_confirmation(
    request: SafeApplySensitivePathRequest,
) -> None:
    if request.confirmation != "APPLY SAFE NGINX BLOCK":
        raise HTTPException(
            status_code=400,
            detail="Confirmation must type exactly 'APPLY SAFE NGINX BLOCK'",
        )
    if not request.ack_backup or not request.ack_risk:
        raise HTTPException(
            status_code=400,
            detail="Backup and risk acknowledgements are required",
        )


def _run_sensitive_path_apply(
    *,
    ssh: SSHConnector,
    finding,
    job_id: int,
    server_id: int,
    nginx_file: str,
    target_url: str,
    modified_content: str,
    patch_preview: str,
    expected: str,
) -> SafeApplySensitivePathResponse:
    backup_path = _backup_path(nginx_file)
    commands: list[str] = []
    rollback_performed = False
    observed = None
    error = None
    status = "resolved"

    try:
        _run_checked(ssh, f"mkdir -p {_quote(_parent_dir(backup_path))}", commands)
        _run_checked(
            ssh,
            f"cp {_quote(nginx_file)} {_quote(backup_path)}",
            commands,
        )
        _write_remote_file(ssh, nginx_file, modified_content, commands)
        nginx_test = ssh.run("nginx -t 2>&1")
        commands.append("nginx -t 2>&1")
        if not nginx_test.success:
            rollback_performed = _rollback_nginx_file(ssh, nginx_file, backup_path, commands)
            status = "error"
            error = f"nginx -t failed: {(nginx_test.stderr or nginx_test.stdout).strip()}"
            return _record_sensitive_apply_result(
                finding=finding,
                job_id=job_id,
                server_id=server_id,
                status=status,
                command=" && ".join(commands),
                expected=expected,
                observed=observed,
                error=error,
                nginx_file=nginx_file,
                target_url=target_url,
                patch_preview=patch_preview,
                backup_path=backup_path,
                rollback_performed=rollback_performed,
            )

        reload_result = ssh.run("systemctl reload nginx")
        commands.append("systemctl reload nginx")
        if not reload_result.success:
            rollback_performed = _rollback_nginx_file(ssh, nginx_file, backup_path, commands)
            status = "error"
            error = f"nginx reload failed: {reload_result.stderr.strip()}"
            return _record_sensitive_apply_result(
                finding=finding,
                job_id=job_id,
                server_id=server_id,
                status=status,
                command=" && ".join(commands),
                expected=expected,
                observed=observed,
                error=error,
                nginx_file=nginx_file,
                target_url=target_url,
                patch_preview=patch_preview,
                backup_path=backup_path,
                rollback_performed=rollback_performed,
            )

        validation_command = sensitive_path_validation_command(target_url)
        validation = ssh.run(validation_command)
        commands.append(validation_command)
        observed = (validation.stdout or validation.stderr or "").strip()
        if not validation.success or not validate_sensitive_path_status(observed):
            rollback_performed = _rollback_nginx_file(ssh, nginx_file, backup_path, commands)
            status = "still_failing"
            error = f"Validation failed: observed {observed or validation.exit_code}"

    except Exception as exc:
        rollback_performed = _rollback_nginx_file(ssh, nginx_file, backup_path, commands)
        status = "error"
        error = str(exc)

    return _record_sensitive_apply_result(
        finding=finding,
        job_id=job_id,
        server_id=server_id,
        status=status,
        command=" && ".join(commands),
        expected=expected,
        observed=observed,
        error=error,
        nginx_file=nginx_file,
        target_url=target_url,
        patch_preview=patch_preview,
        backup_path=backup_path,
        rollback_performed=rollback_performed,
    )


def _record_sensitive_apply_result(
    *,
    finding,
    job_id: int,
    server_id: int,
    status: str,
    command: str,
    expected: str,
    observed: str | None,
    error: str | None,
    nginx_file: str,
    target_url: str,
    patch_preview: str,
    backup_path: str,
    rollback_performed: bool,
) -> SafeApplySensitivePathResponse:
    attempt_id = FixAttemptRepository().create(
        finding_id=finding.id,
        job_id=job_id,
        server_id=server_id,
        rule_id=finding.rule_id,
        action="safe_apply_sensitive_path",
        status=status,
        command=command,
        expected=expected,
        observed=observed,
        error=error,
    )
    fingerprint, target = fingerprint_record(server_id, finding)
    LifecycleEventRepository().create(
        server_id=server_id,
        job_id=job_id,
        finding_fingerprint=fingerprint,
        rule_id=finding.rule_id,
        target=target,
        event_type="validated_resolved" if status == "resolved" else "validation_failed",
        source="safe_apply_sensitive_path",
        details={
            "fix_attempt_id": attempt_id,
            "status": status,
            "expected": expected,
            "observed": observed,
            "error": error,
            "nginx_file": nginx_file,
            "target_url": target_url,
            "backup_path": backup_path,
            "rollback_performed": rollback_performed,
        },
    )
    return SafeApplySensitivePathResponse(
        finding_id=finding.id,
        rule_id=finding.rule_id,
        mode="apply",
        can_apply=True,
        status=status,
        expected=expected,
        nginx_file=nginx_file,
        target_url=target_url,
        patch_preview=patch_preview,
        backup_path=backup_path,
        observed=observed,
        error=error,
        rollback_performed=rollback_performed,
        attempt_id=attempt_id,
    )


def _record_safe_apply_failure(
    *,
    finding,
    server_id: int,
    expected: str,
    error: str,
    nginx_file: str | None,
    target_url: str | None,
) -> SafeApplySensitivePathResponse:
    attempt_id = FixAttemptRepository().create(
        finding_id=finding.id,
        job_id=finding.job_id,
        server_id=server_id,
        rule_id=finding.rule_id,
        action="safe_apply_sensitive_path",
        status="error",
        expected=expected,
        error=error,
    )
    fingerprint, target = fingerprint_record(server_id, finding)
    LifecycleEventRepository().create(
        server_id=server_id,
        job_id=finding.job_id,
        finding_fingerprint=fingerprint,
        rule_id=finding.rule_id,
        target=target,
        event_type="validation_failed",
        source="safe_apply_sensitive_path",
        details={"fix_attempt_id": attempt_id, "status": "error", "error": error},
    )
    return SafeApplySensitivePathResponse(
        finding_id=finding.id,
        rule_id=finding.rule_id,
        mode="apply",
        can_apply=True,
        status="error",
        expected=expected,
        nginx_file=nginx_file,
        target_url=target_url,
        error=error,
        attempt_id=attempt_id,
    )


def _run_checked(ssh: SSHConnector, command: str, commands: list[str]) -> None:
    result = ssh.run(command)
    commands.append(command)
    if not result.success:
        raise RuntimeError(result.stderr or result.stdout or f"Command failed: {command}")


def _write_remote_file(
    ssh: SSHConnector,
    path: str,
    content: str,
    commands: list[str],
) -> None:
    encoded = base64.b64encode(content.encode("utf-8")).decode("ascii")
    temp_path = f"/tmp/serverdoctor-nginx-{datetime.now().strftime('%Y%m%d%H%M%S')}.conf"
    write_command = f"printf %s {_quote(encoded)} | base64 -d > {_quote(temp_path)}"
    move_command = f"mv {_quote(temp_path)} {_quote(path)}"
    _run_checked(ssh, write_command, commands)
    _run_checked(ssh, move_command, commands)


def _rollback_nginx_file(
    ssh: SSHConnector,
    nginx_file: str,
    backup_path: str,
    commands: list[str],
) -> bool:
    rollback = ssh.run(f"cp {_quote(backup_path)} {_quote(nginx_file)}")
    commands.append(f"cp {_quote(backup_path)} {_quote(nginx_file)}")
    if not rollback.success:
        return False
    test = ssh.run("nginx -t 2>&1")
    commands.append("nginx -t 2>&1")
    if test.success:
        reload_result = ssh.run("systemctl reload nginx")
        commands.append("systemctl reload nginx")
        return reload_result.success
    return True


def _backup_path(nginx_file: str) -> str:
    timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    filename = nginx_file.rsplit("/", 1)[-1]
    return f"/etc/nginx/backups/{filename}.serverdoctor-{timestamp}.bak"


def _parent_dir(path: str) -> str:
    return path.rsplit("/", 1)[0]


def _quote(value: str) -> str:
    return "'" + value.replace("'", "'\"'\"'") + "'"
