"""
app/auth/models.py
==================
Pydantic schemas for authentication request/response bodies.
These are API-facing models only — DB operations live in db_manager.py.
"""

from pydantic import BaseModel, Field, field_validator
from typing import Optional
import re


# ── Request models ────────────────────────────────────────────────

class RegisterRequest(BaseModel):
    username: str = Field(..., min_length=3, max_length=32,
                          description="3–32 characters, alphanumeric + underscore only")
    password: str = Field(..., min_length=8, max_length=128,
                          description="Minimum 8 characters")
    role:     str = Field("viewer", description="viewer | analyst | admin")

    @field_validator("username")
    @classmethod
    def username_alphanumeric(cls, v: str) -> str:
        if not re.match(r"^[a-zA-Z0-9_]+$", v):
            raise ValueError("Username may only contain letters, numbers, and underscores")
        return v.lower()

    @field_validator("role")
    @classmethod
    def valid_role(cls, v: str) -> str:
        allowed = {"viewer", "analyst", "admin"}
        if v not in allowed:
            raise ValueError(f"Role must be one of: {', '.join(allowed)}")
        return v


class LoginRequest(BaseModel):
    username: str = Field(..., description="Your username")
    password: str = Field(..., description="Your password")


class RefreshRequest(BaseModel):
    refresh_token: str = Field(..., description="Refresh token from /auth/login")


# ── Response models ───────────────────────────────────────────────

class TokenResponse(BaseModel):
    access_token:  str
    refresh_token: str
    token_type:    str = "bearer"
    expires_in:    int           # seconds until access token expires
    username:      str
    role:          str


class AccessTokenResponse(BaseModel):
    access_token: str
    token_type:   str = "bearer"
    expires_in:   int


class UserResponse(BaseModel):
    user_id:    int
    username:   str
    role:       str
    is_active:  bool
    created_at: str


class MeResponse(BaseModel):
    user_id:   int
    username:  str
    role:      str
    issued_at: Optional[str] = None
    expires_at: Optional[str] = None


# ── Internal token payload (not exposed in API responses) ─────────

class TokenPayload(BaseModel):
    sub:      str           # username
    user_id:  int
    role:     str
    type:     str           # "access" | "refresh"
    exp:      int           # unix timestamp
    iat:      int           # issued at
