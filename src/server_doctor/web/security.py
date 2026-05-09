"""Local web authentication and CSRF helpers."""

from __future__ import annotations

import hmac
import os
import secrets
import time
from dataclasses import dataclass

from fastapi import Cookie, Depends, Header, HTTPException, Response

SESSION_COOKIE = "serverdoctor_session"
CSRF_HEADER = "x-serverdoctor-csrf"
SESSION_TTL_SECONDS = 12 * 60 * 60


@dataclass
class Session:
    token: str
    csrf_token: str
    created_at: float


_sessions: dict[str, Session] = {}


def _configured_password() -> str:
    password = os.getenv("SERVER_DOCTOR_WEB_PASSWORD", "")
    if not password:
        raise HTTPException(
            status_code=503,
            detail="SERVER_DOCTOR_WEB_PASSWORD is required",
        )
    return password


def verify_password(password: str) -> bool:
    return hmac.compare_digest(password, _configured_password())


def create_session(response: Response) -> Session:
    token = secrets.token_urlsafe(32)
    csrf = secrets.token_urlsafe(32)
    session = Session(token=token, csrf_token=csrf, created_at=time.time())
    _sessions[token] = session
    response.set_cookie(
        SESSION_COOKIE,
        token,
        httponly=True,
        samesite="strict",
        secure=False,
        max_age=SESSION_TTL_SECONDS,
    )
    return session


def clear_session(response: Response, serverdoctor_session: str | None = None) -> None:
    if serverdoctor_session:
        _sessions.pop(serverdoctor_session, None)
    response.delete_cookie(SESSION_COOKIE, httponly=True, samesite="strict")


def require_auth(serverdoctor_session: str | None = Cookie(default=None)) -> Session:
    if not serverdoctor_session:
        raise HTTPException(status_code=401, detail="Authentication required")

    session = _sessions.get(serverdoctor_session)
    if not session:
        raise HTTPException(status_code=401, detail="Invalid session")

    if time.time() - session.created_at > SESSION_TTL_SECONDS:
        _sessions.pop(serverdoctor_session, None)
        raise HTTPException(status_code=401, detail="Session expired")

    return session


def optional_auth(serverdoctor_session: str | None = Cookie(default=None)) -> Session | None:
    if not serverdoctor_session:
        return None
    session = _sessions.get(serverdoctor_session)
    if not session:
        return None
    if time.time() - session.created_at > SESSION_TTL_SECONDS:
        _sessions.pop(serverdoctor_session, None)
        return None
    return session


def require_csrf(
    session: Session = Depends(require_auth),  # noqa: B008
    csrf: str | None = Header(default=None, alias=CSRF_HEADER),
) -> None:
    if not csrf or not hmac.compare_digest(csrf, session.csrf_token):
        raise HTTPException(status_code=403, detail="Invalid CSRF token")
