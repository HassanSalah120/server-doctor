"""Registry-defined safe server actions."""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel

from server_doctor.utils.redaction import redact_text


class SafeActionRequest(BaseModel):
    server_id: int
    action_id: str
    args: dict[str, str] = {}
    mode: Literal["preview", "run"] = "preview"


class SafeActionResponse(BaseModel):
    action_id: str
    mode: str
    command: str
    risk: str
    requires_confirmation: bool
    output: str | None = None
    error: str | None = None


SAFE_ACTIONS = {
    "nginx_test": {
        "command": "sudo nginx -t",
        "risk": "low",
        "run_allowed": True,
    },
    "list_open_ports": {
        "command": "ss -ltnp",
        "risk": "low",
        "run_allowed": True,
    },
    "nginx_reload": {
        "command": "sudo systemctl reload nginx",
        "risk": "medium",
        "run_allowed": False,
    },
    "failed_units": {
        "command": "systemctl --failed --no-pager",
        "risk": "low",
        "run_allowed": True,
    },
    "disk_usage": {
        "command": "df -h",
        "risk": "low",
        "run_allowed": True,
    },
}


def build_safe_action_response(
    request: SafeActionRequest,
    *,
    ssh=None,
) -> SafeActionResponse:
    action = SAFE_ACTIONS.get(request.action_id)
    if not action:
        raise KeyError(request.action_id)
    command = action["command"]
    if request.mode == "run" and not action["run_allowed"]:
        raise PermissionError("This action is preview-only")
    if request.mode == "preview":
        return SafeActionResponse(
            action_id=request.action_id,
            mode=request.mode,
            command=command,
            risk=action["risk"],
            requires_confirmation=not action["run_allowed"],
        )
    result = ssh.run(command)
    return SafeActionResponse(
        action_id=request.action_id,
        mode=request.mode,
        command=command,
        risk=action["risk"],
        requires_confirmation=False,
        output=redact_text(result.stdout),
        error=redact_text(result.stderr) if result.stderr else None,
    )
