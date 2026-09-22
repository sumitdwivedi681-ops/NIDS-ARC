"""
Authentication API Endpoints.

POST /api/v1/auth/login — Authenticate and get tokens
POST /api/v1/auth/refresh — Refresh access token
POST /api/v1/auth/logout — Logout (client-side token discard)
GET  /api/v1/auth/me — Get current user info
"""

from __future__ import annotations

from datetime import datetime, timezone

import structlog
from fastapi import APIRouter, Depends
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from backend.database import get_db
from backend.middleware.auth import (
    CurrentUser,
    create_access_token,
    create_refresh_token,
    decode_token,
    get_current_user,
    hash_password,
    verify_password,
)
from backend.middleware.error_handler import AuthenticationError
from backend.models.user import User
from backend.models.audit_log import AuditLog
from backend.schemas.auth import LoginRequest, TokenResponse, RefreshRequest, UserResponse
from backend.config import get_settings

logger = structlog.get_logger("auth_api")
router = APIRouter(prefix="/auth", tags=["Authentication"])


@router.post("/login", response_model=TokenResponse)
async def login(request: LoginRequest, db: AsyncSession = Depends(get_db)):
    """Authenticate user and return JWT tokens."""
    settings = get_settings()

    # Find user
    result = await db.execute(select(User).where(User.username == request.username))
    user = result.scalar_one_or_none()

    if user is None or not user.is_active:
        logger.warning("login_failed", username=request.username, reason="user_not_found_or_inactive")
        # Log failed attempt
        audit = AuditLog(
            action="login_failed",
            resource_type="auth",
            actor_username=request.username,
            details={"reason": "user_not_found_or_inactive"},
            result="failure",
        )
        db.add(audit)
        raise AuthenticationError("Invalid username or password")

    # Check lockout
    if user.locked_until and user.locked_until > datetime.now(timezone.utc):
        logger.warning("login_failed", username=request.username, reason="account_locked")
        raise AuthenticationError("Account is temporarily locked")

    # Verify password
    if not verify_password(request.password, user.password_hash):
        user.failed_login_attempts += 1
        if user.failed_login_attempts >= 5:
            from datetime import timedelta
            user.locked_until = datetime.now(timezone.utc) + timedelta(minutes=15)
            logger.warning("account_locked", username=request.username)

        audit = AuditLog(
            action="login_failed",
            resource_type="auth",
            actor_id=user.id,
            actor_username=user.username,
            details={"reason": "invalid_password", "attempts": user.failed_login_attempts},
            result="failure",
        )
        db.add(audit)
        raise AuthenticationError("Invalid username or password")

    # Success — reset failed attempts
    user.failed_login_attempts = 0
    user.locked_until = None
    user.last_login = datetime.now(timezone.utc)

    access_token = create_access_token(user.id, user.username, user.role)
    refresh_token = create_refresh_token(user.id)

    # Audit log
    audit = AuditLog(
        action="login_success",
        resource_type="auth",
        actor_id=user.id,
        actor_username=user.username,
        result="success",
    )
    db.add(audit)

    logger.info("login_success", username=user.username, role=user.role)

    return TokenResponse(
        access_token=access_token,
        refresh_token=refresh_token,
        expires_in=settings.jwt_access_token_expire_minutes * 60,
    )


@router.post("/refresh", response_model=TokenResponse)
async def refresh_token(request: RefreshRequest, db: AsyncSession = Depends(get_db)):
    """Refresh an access token using a refresh token."""
    settings = get_settings()
    payload = decode_token(request.refresh_token)

    if payload.get("type") != "refresh":
        raise AuthenticationError("Invalid refresh token")

    user_id = payload["sub"]
    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()

    if user is None or not user.is_active:
        raise AuthenticationError("User not found or inactive")

    access_token = create_access_token(user.id, user.username, user.role)
    new_refresh_token = create_refresh_token(user.id)

    return TokenResponse(
        access_token=access_token,
        refresh_token=new_refresh_token,
        expires_in=settings.jwt_access_token_expire_minutes * 60,
    )


@router.post("/logout")
async def logout(current_user: CurrentUser = Depends(get_current_user)):
    """Logout — client should discard tokens."""
    logger.info("logout", username=current_user.username)
    return {"message": "Logged out successfully"}


@router.get("/me")
async def get_me(
    current_user: CurrentUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Get current authenticated user info."""
    result = await db.execute(select(User).where(User.id == current_user.user_id))
    user = result.scalar_one_or_none()
    if user is None:
        raise AuthenticationError("User not found")
    return {
        "id": user.id,
        "username": user.username,
        "email": user.email,
        "role": user.role,
        "is_active": user.is_active,
        "last_login": user.last_login.isoformat() if user.last_login else None,
    }
