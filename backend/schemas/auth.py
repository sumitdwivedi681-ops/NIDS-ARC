"""Auth Pydantic schemas."""

from __future__ import annotations

from typing import Optional

from pydantic import BaseModel, Field


class LoginRequest(BaseModel):
    """Login request."""
    username: str = Field(min_length=1, max_length=50)
    password: str = Field(min_length=1)


class TokenResponse(BaseModel):
    """JWT token response."""
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int


class RefreshRequest(BaseModel):
    """Token refresh request."""
    refresh_token: str


class UserCreate(BaseModel):
    """Create user request."""
    username: str = Field(min_length=3, max_length=50)
    email: str = Field(max_length=255)
    password: str = Field(min_length=8)
    role: str = "viewer"


class UserResponse(BaseModel):
    """User response — never includes password_hash."""
    id: str
    username: str
    email: str
    role: str
    is_active: bool
    last_login: Optional[str] = None
    created_at: str

    model_config = {"from_attributes": True}


class UserUpdate(BaseModel):
    """Update user request."""
    email: Optional[str] = None
    role: Optional[str] = None
    is_active: Optional[bool] = None
