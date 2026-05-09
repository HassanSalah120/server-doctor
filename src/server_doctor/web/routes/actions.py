"""Safe registry-defined server actions."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException

from server_doctor.connector.ssh import SSHConfig, SSHConnector
from server_doctor.engine.actions import (
    SafeActionRequest,
    SafeActionResponse,
    build_safe_action_response,
)
from server_doctor.storage.repositories import ServerRepository
from server_doctor.web.secrets import get_server_key_passphrase, get_server_password
from server_doctor.web.security import require_auth, require_csrf

router = APIRouter(dependencies=[Depends(require_auth)])
_servers = ServerRepository()


@router.post(
    "/actions/safe",
    response_model=SafeActionResponse,
    dependencies=[Depends(require_csrf)],
)
async def run_safe_action(request: SafeActionRequest) -> SafeActionResponse:
    server = _servers.get_by_id(request.server_id)
    if not server:
        raise HTTPException(status_code=404, detail="Server not found")
    try:
        if request.mode == "preview":
            return build_safe_action_response(request)
        password = request.args.get("one_time_password") or get_server_password(
            server.password_secret_ref
        ) or server.password
        passphrase = request.args.get(
            "one_time_key_passphrase"
        ) or get_server_key_passphrase(server.key_passphrase_secret_ref)
        config = SSHConfig(
            host=server.host,
            user=server.username,
            port=server.port,
            key_path=server.key_path,
            passphrase=passphrase,
            password=password,
            use_sudo=True,
        )
        with SSHConnector(config) as ssh:
            return build_safe_action_response(request, ssh=ssh)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail="Unknown safe action") from exc
    except PermissionError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
