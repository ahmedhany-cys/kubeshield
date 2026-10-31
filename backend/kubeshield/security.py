"""Authentication, authorisation and request hardening."""

from __future__ import annotations

import hmac
import threading
import time
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

import jwt
from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError
from fastapi import Depends, HTTPException, Request, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from kubeshield.config import get_settings
from kubeshield.db import get_db
from kubeshield.models import User

SESSION_COOKIE = "ks_session"
ROLES = ("viewer", "responder", "admin")
_ROLE_RANK = {r: i for i, r in enumerate(ROLES)}
_hasher = PasswordHasher()
# Pre-computed hash used to keep login timing constant for unknown users.
_DUMMY_HASH = _hasher.hash("kubeshield-timing-equaliser")


def hash_password(password: str) -> str:
    return _hasher.hash(password)


def verify_password(password_hash: str, password: str) -> bool:
    try:
        return _hasher.verify(password_hash, password)
    except (VerificationError, InvalidHashError):
        return False


def authenticate(db: Session, username: str, password: str) -> User | None:
    user = db.scalar(select(User).where(User.username == username))
    if user is None or not user.is_active:
        verify_password(_DUMMY_HASH, password)
        return None
    return user if verify_password(user.password_hash, password) else None


def issue_token(user: User) -> str:
    s = get_settings()
    now = datetime.now(UTC)
    payload = {
        "sub": user.username,
        "role": user.role,
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(minutes=s.session_ttl_minutes)).timestamp()),
        "iss": "kubeshield",
    }
    return jwt.encode(payload, s.jwt_secret.get_secret_value(), algorithm="HS256")


@dataclass(frozen=True)
class Principal:
    username: str
    role: str

    def has(self, role: str) -> bool:
        return _ROLE_RANK[self.role] >= _ROLE_RANK[role]


def current_user(request: Request, db: Session = Depends(get_db)) -> Principal:
    token = request.cookies.get(SESSION_COOKIE)
    auth = request.headers.get("authorization", "")
    if not token and auth.lower().startswith("bearer "):
        token = auth[7:]
    if not token:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "authentication required")
    try:
        claims = jwt.decode(
            token,
            get_settings().jwt_secret.get_secret_value(),
            algorithms=["HS256"],
            issuer="kubeshield",
            options={"require": ["exp", "sub", "iss"]},
        )
    except jwt.PyJWTError as exc:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "invalid or expired session") from exc
    # Re-check the account on every request so disabled users lose access immediately.
    user = db.scalar(select(User).where(User.username == claims["sub"]))
    if user is None or not user.is_active:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "account disabled")
    return Principal(user.username, user.role)


def require_role(role: str):
    def dependency(principal: Principal = Depends(current_user)) -> Principal:
        if not principal.has(role):
            raise HTTPException(status.HTTP_403_FORBIDDEN, f"{role} role required")
        return principal

    return dependency


def verify_ingest_token(request: Request) -> None:
    auth = request.headers.get("authorization", "")
    supplied = auth[7:] if auth.lower().startswith("bearer ") else ""
    expected = get_settings().ingest_token.get_secret_value()
    if not supplied or not hmac.compare_digest(supplied.encode(), expected.encode()):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "invalid ingest token")


class LoginRateLimiter:
    """Small in-process limiter: N failed attempts per key per window."""

    def __init__(self, max_attempts: int = 5, window_seconds: int = 300) -> None:
        self.max_attempts = max_attempts
        self.window = window_seconds
        self._failures: dict[str, list[float]] = {}
        self._lock = threading.Lock()

    def _prune(self, key: str, now: float) -> list[float]:
        recent = [t for t in self._failures.get(key, []) if now - t < self.window]
        self._failures[key] = recent
        return recent

    def blocked(self, key: str) -> bool:
        with self._lock:
            return len(self._prune(key, time.monotonic())) >= self.max_attempts

    def fail(self, key: str) -> None:
        with self._lock:
            self._prune(key, time.monotonic()).append(time.monotonic())

    def reset(self, key: str) -> None:
        with self._lock:
            self._failures.pop(key, None)


login_limiter = LoginRateLimiter()
