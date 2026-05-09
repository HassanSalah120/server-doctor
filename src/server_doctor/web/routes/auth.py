"""Authentication routes for the local ServerDoctor web API."""

from fastapi import APIRouter, Cookie, Depends, HTTPException, Response
from pydantic import BaseModel

from server_doctor.web.security import (
    SESSION_COOKIE,
    clear_session,
    create_session,
    optional_auth,
    verify_password,
)

router = APIRouter(prefix="/auth", tags=["auth"])


class LoginRequest(BaseModel):
    password: str


class AuthStatusResponse(BaseModel):
    authenticated: bool
    csrf_token: str | None = None


@router.post("/login", response_model=AuthStatusResponse)
async def login(request: LoginRequest, response: Response) -> AuthStatusResponse:
    if not verify_password(request.password):
        raise HTTPException(status_code=401, detail="Invalid password")
    session = create_session(response)
    return AuthStatusResponse(authenticated=True, csrf_token=session.csrf_token)


@router.post("/logout", response_model=AuthStatusResponse)
async def logout(
    response: Response,
    serverdoctor_session: str | None = Cookie(default=None, alias=SESSION_COOKIE),
) -> AuthStatusResponse:
    clear_session(response, serverdoctor_session)
    return AuthStatusResponse(authenticated=False, csrf_token=None)


@router.get("/status", response_model=AuthStatusResponse)
async def status(session=Depends(optional_auth)) -> AuthStatusResponse:  # noqa: B008
    if not session:
        return AuthStatusResponse(authenticated=False, csrf_token=None)
    return AuthStatusResponse(authenticated=True, csrf_token=session.csrf_token)
