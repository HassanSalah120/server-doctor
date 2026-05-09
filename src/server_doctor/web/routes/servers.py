"""Server management API routes.

Endpoints:
    POST /api/servers      - Create a server
    GET  /api/servers      - List all servers
    GET  /api/servers/{id} - Get server details
"""


from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

from server_doctor.config import ConfigManager
from server_doctor.connector.ssh import SSHConfig
from server_doctor.storage.repositories import ServerRepository
from server_doctor.web.secrets import (
    SecretStorageError,
    delete_server_key_passphrase,
    delete_server_password,
    get_server_key_passphrase,
    get_server_password,
    store_server_key_passphrase,
    store_server_password,
)
from server_doctor.web.security import require_auth, require_csrf

router = APIRouter(dependencies=[Depends(require_auth)])
_repo = ServerRepository()


class CreateServerRequest(BaseModel):
    """Request body for creating a server."""

    name: str = Field(..., description="Display name for the server")
    host: str = Field(..., description="Server hostname or IP")
    port: int = Field(22, description="SSH port")
    username: str = Field("root", description="SSH username")
    password: str | None = Field(None, description="SSH password (if not using key)")
    key_path: str | None = Field(None, description="Path to SSH private key")
    key_passphrase: str | None = Field(
        None,
        description="Passphrase for encrypted SSH private key",
    )
    tags: str = Field("", description="Comma-separated tags")


class UpdateServerRequest(BaseModel):
    """Request body for updating a server."""

    name: str | None = Field(None, description="Display name for the server")
    host: str | None = Field(None, description="Server hostname or IP")
    port: int | None = Field(None, description="SSH port")
    username: str | None = Field(None, description="SSH username")
    password: str | None = Field(None, description="SSH password (set null to clear)")
    key_path: str | None = Field(
        None,
        description="Path to SSH private key (set null to clear)",
    )
    key_passphrase: str | None = Field(
        None,
        description="Passphrase for encrypted SSH private key (set null to clear)",
    )
    tags: str | None = Field(None, description="Comma-separated tags")


@router.post("/servers", dependencies=[Depends(require_csrf)])
async def create_server(request: CreateServerRequest) -> dict:
    """Register a new server."""
    password_secret_ref = None
    password_storage = "none"
    key_passphrase_secret_ref = None
    key_passphrase_storage = "none"
    if request.password:
        try:
            password_secret_ref = store_server_password(
                request.name,
                request.host,
                request.password,
            )
            password_storage = "keyring"
        except SecretStorageError as exc:
            raise HTTPException(status_code=500, detail=str(exc)) from exc
    if request.key_passphrase:
        try:
            key_passphrase_secret_ref = store_server_key_passphrase(
                request.name,
                request.host,
                request.key_passphrase,
            )
            key_passphrase_storage = "keyring"
        except SecretStorageError as exc:
            delete_server_password(password_secret_ref)
            raise HTTPException(status_code=500, detail=str(exc)) from exc

    try:
        server_id = _repo.create(
            name=request.name,
            host=request.host,
            port=request.port,
            username=request.username,
            password=None,
            password_secret_ref=password_secret_ref,
            password_storage=password_storage,
            key_path=request.key_path,
            key_passphrase_secret_ref=key_passphrase_secret_ref,
            key_passphrase_storage=key_passphrase_storage,
            tags=request.tags,
        )
    except Exception:
        delete_server_password(password_secret_ref)
        delete_server_key_passphrase(key_passphrase_secret_ref)
        raise
    server = _repo.get_by_id(server_id)
    if not server:
        delete_server_password(password_secret_ref)
        delete_server_key_passphrase(key_passphrase_secret_ref)
        raise HTTPException(status_code=500, detail="Failed to create server")

    config_mgr = ConfigManager()
    config_mgr.add_profile(
        server.name,
        SSHConfig(
            host=server.host,
            user=server.username,
            port=server.port,
            key_path=server.key_path,
            passphrase=get_server_key_passphrase(server.key_passphrase_secret_ref),
            use_sudo=True,
            password=get_server_password(server.password_secret_ref),
        ),
    )
    return {"server": server.to_dict()}


@router.get("/servers")
async def list_servers() -> dict:
    """List all registered servers."""
    servers = _repo.get_all()
    return {"servers": [s.to_dict() for s in servers]}


@router.get("/servers/{server_id}")
async def get_server(server_id: int) -> dict:
    """Get a server by ID."""
    server = _repo.get_by_id(server_id)
    if not server:
        raise HTTPException(status_code=404, detail="Server not found")
    return {"server": server.to_dict()}


@router.put("/servers/{server_id}", dependencies=[Depends(require_csrf)])
async def update_server(server_id: int, request: UpdateServerRequest) -> dict:
    """Update an existing server."""
    server = _repo.get_by_id(server_id)
    if not server:
        raise HTTPException(status_code=404, detail="Server not found")

    fields_set = getattr(request, "model_fields_set", None)
    if fields_set is None:
        fields_set = getattr(request, "__fields_set__", set())

    update_kwargs: dict = {
        "name": request.name,
        "host": request.host,
        "port": request.port,
        "username": request.username,
        "tags": request.tags,
    }
    replacement_secret_ref = None
    replacement_key_passphrase_ref = None
    old_secret_ref = server.password_secret_ref
    old_key_passphrase_ref = server.key_passphrase_secret_ref
    if "password" in fields_set:
        if request.password:
            try:
                replacement_secret_ref = store_server_password(
                    request.name or server.name,
                    request.host or server.host,
                    request.password,
                )
            except SecretStorageError as exc:
                raise HTTPException(status_code=500, detail=str(exc)) from exc
            update_kwargs["password"] = None
            update_kwargs["password_secret_ref"] = replacement_secret_ref
            update_kwargs["password_storage"] = "keyring"
        else:
            update_kwargs["password"] = None
            update_kwargs["password_secret_ref"] = None
            update_kwargs["password_storage"] = "none"
    if "key_path" in fields_set:
        update_kwargs["key_path"] = request.key_path
    if "key_passphrase" in fields_set:
        if request.key_passphrase:
            try:
                replacement_key_passphrase_ref = store_server_key_passphrase(
                    request.name or server.name,
                    request.host or server.host,
                    request.key_passphrase,
                )
            except SecretStorageError as exc:
                delete_server_password(replacement_secret_ref)
                raise HTTPException(status_code=500, detail=str(exc)) from exc
            update_kwargs["key_passphrase_secret_ref"] = replacement_key_passphrase_ref
            update_kwargs["key_passphrase_storage"] = "keyring"
        else:
            update_kwargs["key_passphrase_secret_ref"] = None
            update_kwargs["key_passphrase_storage"] = "none"

    try:
        updated = _repo.update(server_id, **update_kwargs)
        if not updated:
            delete_server_password(replacement_secret_ref)
            delete_server_key_passphrase(replacement_key_passphrase_ref)
            raise HTTPException(status_code=400, detail="No fields updated")
    except Exception:
        delete_server_password(replacement_secret_ref)
        delete_server_key_passphrase(replacement_key_passphrase_ref)
        raise

    if "password" in fields_set:
        delete_server_password(old_secret_ref)
    if "key_passphrase" in fields_set:
        delete_server_key_passphrase(old_key_passphrase_ref)

    fresh = _repo.get_by_id(server_id)
    if not fresh:
        raise HTTPException(status_code=500, detail="Failed to load updated server")

    if fresh.name != server.name:
        config_mgr = ConfigManager()
        config_mgr.remove_profile(server.name)

    config_mgr = ConfigManager()
    config_mgr.add_profile(
        fresh.name,
        SSHConfig(
            host=fresh.host,
            user=fresh.username,
            port=fresh.port,
            key_path=fresh.key_path,
            passphrase=get_server_key_passphrase(fresh.key_passphrase_secret_ref),
            use_sudo=True,
            password=get_server_password(fresh.password_secret_ref) or fresh.password,
        ),
    )
    return {"server": fresh.to_dict()}


@router.delete("/servers/{server_id}", dependencies=[Depends(require_csrf)])
async def delete_server(
    server_id: int,
    cascade: bool = Query(False, description="Also delete associated scan jobs"),
) -> dict:
    """Delete a server.

    If ``cascade`` is true, any scan jobs linked to the server will be
    removed first.  Otherwise we mimic strict foreign-key behaviour and
    return a 400 error when jobs are present.

    A 404 is returned when the server simply doesn’t exist.
    """
    server = _repo.get_by_id(server_id)
    if not server:
        raise HTTPException(status_code=404, detail="Server not found")

    jobs_removed = 0
    if cascade:
        from server_doctor.storage.repositories import ScanJobRepository

        job_repo = ScanJobRepository()
        jobs_removed = job_repo.delete_by_server_id(server_id)

    deleted = _repo.delete(server_id)
    if not deleted:
        raise HTTPException(
            status_code=400,
            detail="Cannot delete server with existing scan jobs; delete jobs first",
        )

    config_mgr = ConfigManager()
    config_mgr.remove_profile(server.name)
    delete_server_password(server.password_secret_ref)
    delete_server_key_passphrase(server.key_passphrase_secret_ref)

    result = {"deleted": True}
    if cascade:
        result["jobs_deleted"] = jobs_removed
    return result
