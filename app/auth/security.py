"""
app/auth/security.py
====================
Password hashing  — PBKDF2-SHA256 via stdlib hashlib (no bcrypt needed)
JWT encoding      — PyJWT (already in requirements)
FastAPI deps      — verify_token(), require_role() used as Depends()

Password storage format:
  pbkdf2_sha256$<iterations>$<salt_hex>$<hash_hex>
  e.g. pbkdf2_sha256$260000$a1b2c3...$d4e5f6...

This mirrors Django's password hasher format so the logic is auditable.
"""

import os
import hashlib
import hmac
import secrets
from datetime import datetime, timezone, timedelta
from typing import Optional

import jwt
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials

from app.utils.logger import get_logger

logger = get_logger(__name__)

# ── Configuration (override via environment variables) ────────────
SECRET_KEY         = os.getenv("JWT_SECRET_KEY", secrets.token_hex(32))
ALGORITHM          = "HS256"
ACCESS_TOKEN_MINS  = int(os.getenv("JWT_ACCESS_EXPIRE_MINUTES",  "30"))
REFRESH_TOKEN_DAYS = int(os.getenv("JWT_REFRESH_EXPIRE_DAYS",    "7"))
PBKDF2_ITERATIONS  = int(os.getenv("PBKDF2_ITERATIONS",          "260000"))

# Role hierarchy — higher index = more permissions
ROLE_HIERARCHY = ["viewer", "analyst", "admin"]

# HTTP Bearer scheme — reads "Authorization: Bearer <token>"
bearer_scheme = HTTPBearer(auto_error=False)


# ── Password Hashing ──────────────────────────────────────────────

def hash_password(password: str) -> str:
    """
    Hash a plaintext password using PBKDF2-SHA256.
    Returns a string: 'pbkdf2_sha256$<iters>$<salt_hex>$<hash_hex>'
    """
    salt = secrets.token_hex(16)          # 32-char hex = 16 bytes
    dk   = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt.encode("utf-8"),
        PBKDF2_ITERATIONS,
        dklen=32,
    )
    return f"pbkdf2_sha256${PBKDF2_ITERATIONS}${salt}${dk.hex()}"


def verify_password(plaintext: str, stored_hash: str) -> bool:
    """
    Constant-time comparison of plaintext against stored PBKDF2 hash.
    Returns True if passwords match.
    """
    try:
        parts = stored_hash.split("$")
        if len(parts) != 4 or parts[0] != "pbkdf2_sha256":
            return False
        _, iters_str, salt, expected_hex = parts
        iters = int(iters_str)
        dk = hashlib.pbkdf2_hmac(
            "sha256",
            plaintext.encode("utf-8"),
            salt.encode("utf-8"),
            iters,
            dklen=32,
        )
        return hmac.compare_digest(dk.hex(), expected_hex)
    except Exception:
        return False


# ── JWT Token Creation ────────────────────────────────────────────

def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def create_access_token(user_id: int, username: str, role: str) -> tuple[str, int]:
    """
    Create a signed JWT access token.
    Returns (token_string, expires_in_seconds).
    """
    now    = _utcnow()
    expire = now + timedelta(minutes=ACCESS_TOKEN_MINS)
    payload = {
        "sub":     username,
        "user_id": user_id,
        "role":    role,
        "type":    "access",
        "iat":     int(now.timestamp()),
        "exp":     int(expire.timestamp()),
    }
    token = jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)
    return token, ACCESS_TOKEN_MINS * 60


def create_refresh_token(user_id: int, username: str) -> tuple[str, str]:
    """
    Create a signed JWT refresh token.
    Returns (token_string, jti) where jti is the unique token ID
    stored in the DB for revocation.
    """
    now    = _utcnow()
    expire = now + timedelta(days=REFRESH_TOKEN_DAYS)
    jti    = secrets.token_hex(16)   # unique token identifier

    payload = {
        "sub":     username,
        "user_id": user_id,
        "type":    "refresh",
        "jti":     jti,
        "iat":     int(now.timestamp()),
        "exp":     int(expire.timestamp()),
    }
    token = jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)
    return token, jti


def decode_token(token: str) -> dict:
    """
    Decode and validate a JWT token.
    Raises HTTPException 401 on any failure.
    """
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload
    except jwt.ExpiredSignatureError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token has expired. Please log in again.",
            headers={"WWW-Authenticate": "Bearer"},
        )
    except jwt.InvalidTokenError as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Invalid token: {str(e)}",
            headers={"WWW-Authenticate": "Bearer"},
        )


# ── FastAPI Dependencies ──────────────────────────────────────────

def verify_token(
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(bearer_scheme),
) -> dict:
    """
    FastAPI dependency — validates Bearer token on protected routes.
    Usage: @app.get("/protected") def route(user=Depends(verify_token))

    Returns the decoded token payload dict:
      {"sub": "alice", "user_id": 1, "role": "analyst", ...}
    """
    if not credentials:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required. Include 'Authorization: Bearer <token>' header.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    payload = decode_token(credentials.credentials)

    # Must be an access token (not a refresh token used on a regular endpoint)
    if payload.get("type") != "access":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token type. Use the access token, not the refresh token.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    return payload


def require_role(minimum_role: str):
    """
    FastAPI dependency factory — requires a minimum role level.
    Usage: @app.post("/admin-only") def route(user=Depends(require_role("admin")))

    Role hierarchy: viewer < analyst < admin
    """
    def _check_role(user: dict = Depends(verify_token)) -> dict:
        user_role = user.get("role", "viewer")
        try:
            user_level    = ROLE_HIERARCHY.index(user_role)
            required_level = ROLE_HIERARCHY.index(minimum_role)
        except ValueError:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Unknown role: '{user_role}'.",
            )
        if user_level < required_level:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=(
                    f"Insufficient permissions. "
                    f"Required: '{minimum_role}', your role: '{user_role}'."
                ),
            )
        return user
    return _check_role
