"""
app/auth/router.py
==================
Authentication endpoints:

  POST /auth/register  — create a new user account
  POST /auth/login     — authenticate, receive access + refresh tokens
  POST /auth/refresh   — exchange refresh token for new access token
  POST /auth/logout    — revoke refresh token (invalidates session)
  GET  /auth/me        — return current user info from token
  GET  /auth/users     — list all users (admin only)
  DELETE /auth/users/{user_id} — deactivate user (admin only)
"""

from fastapi import APIRouter, HTTPException, Depends, status
from datetime import datetime, timezone, timedelta
import os

from app.auth.models import (
    RegisterRequest, LoginRequest, RefreshRequest,
    TokenResponse, AccessTokenResponse, UserResponse, MeResponse,
)
from app.auth.security import (
    hash_password, verify_password,
    create_access_token, create_refresh_token,
    decode_token, verify_token, require_role,
)
from app.database.db_manager import (
    create_user, get_user_by_username, get_user_by_id,
    update_last_login, list_users, deactivate_user,
    store_refresh_token, is_refresh_token_valid, revoke_refresh_token,
    revoke_all_user_tokens,
)
from app.utils.logger import get_logger

logger = get_logger(__name__)

router = APIRouter(prefix="/auth", tags=["Authentication"])

REFRESH_TOKEN_DAYS = int(os.getenv("JWT_REFRESH_EXPIRE_DAYS", "7"))


def _expires_at_str(days: int) -> str:
    """ISO string for token expiry, used for DB storage."""
    expire = datetime.now(timezone.utc) + timedelta(days=days)
    return expire.isoformat()


# ── Register ──────────────────────────────────────────────────────

@router.post("/register", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
def register(request: RegisterRequest):
    """
    Create a new user account.

    - Usernames are case-insensitive (stored lowercase)
    - Passwords are hashed with PBKDF2-SHA256 (never stored plaintext)
    - Default role is 'viewer' — request 'analyst' or 'admin' explicitly
    - In production, restrict 'admin' registration to existing admins
    """
    try:
        pw_hash = hash_password(request.password)
        user    = create_user(request.username, pw_hash, request.role)
        logger.info("New user registered: %s (role=%s)", user["username"], user["role"])
        return UserResponse(
            user_id=user["user_id"],
            username=user["username"],
            role=user["role"],
            is_active=True,
            created_at=datetime.now(timezone.utc).isoformat(),
        )
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(e))
    except Exception as e:
        logger.error("Registration failed for %s: %s", request.username, str(e))
        raise HTTPException(status_code=500, detail="Registration failed.")


# ── Login ─────────────────────────────────────────────────────────

@router.post("/login", response_model=TokenResponse)
def login(request: LoginRequest):
    """
    Authenticate with username + password.

    Returns:
    - access_token  — short-lived JWT (30 min), use on every protected request
    - refresh_token — long-lived JWT (7 days), use only on /auth/refresh
    - token_type    — always "bearer"
    - expires_in    — access token lifetime in seconds

    Use the access token as: Authorization: Bearer <access_token>
    """
    user = get_user_by_username(request.username)

    # Constant-time failure — don't reveal whether username exists
    if not user or not verify_password(request.password, user["password_hash"]):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    if not user["is_active"]:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Account has been deactivated. Contact an administrator.",
        )

    access_token,  expires_in = create_access_token(user["id"], user["username"], user["role"])
    refresh_token, jti        = create_refresh_token(user["id"], user["username"])

    store_refresh_token(jti, user["id"], _expires_at_str(REFRESH_TOKEN_DAYS))
    update_last_login(user["id"])

    logger.info("User logged in: %s", user["username"])

    return TokenResponse(
        access_token=access_token,
        refresh_token=refresh_token,
        expires_in=expires_in,
        username=user["username"],
        role=user["role"],
    )


# ── Refresh ───────────────────────────────────────────────────────

@router.post("/refresh", response_model=AccessTokenResponse)
def refresh_token(request: RefreshRequest):
    """
    Exchange a valid refresh token for a new access token.

    - Refresh tokens expire after 7 days
    - Refresh tokens are invalidated on /auth/logout
    - Refresh tokens are stored server-side for revocation support
    """
    payload = decode_token(request.refresh_token)

    if payload.get("type") != "refresh":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token type. Provide a refresh token.",
        )

    jti = payload.get("jti")
    if not jti or not is_refresh_token_valid(jti):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Refresh token has been revoked or expired. Please log in again.",
        )

    user = get_user_by_id(payload["user_id"])
    if not user or not user["is_active"]:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User account not found or deactivated.",
        )

    access_token, expires_in = create_access_token(user["id"], user["username"], user["role"])

    return AccessTokenResponse(
        access_token=access_token,
        expires_in=expires_in,
    )


# ── Logout ────────────────────────────────────────────────────────

@router.post("/logout", status_code=status.HTTP_200_OK)
def logout(request: RefreshRequest):
    """
    Revoke the provided refresh token (logout from this device).

    This invalidates the refresh token server-side so it cannot be
    used to obtain new access tokens. Existing access tokens remain
    valid until they expire (max 30 min).

    To log out from ALL devices, use /auth/logout-all.
    """
    try:
        payload = decode_token(request.refresh_token)
        jti     = payload.get("jti")
        if jti:
            revoke_refresh_token(jti)
            logger.info("User logged out: %s", payload.get("sub"))
    except HTTPException:
        pass  # expired tokens should still return 200
    return {"message": "Logged out successfully."}


@router.post("/logout-all", status_code=status.HTTP_200_OK)
def logout_all(user: dict = Depends(verify_token)):
    """
    Revoke ALL refresh tokens for the current user (logout everywhere).
    Requires a valid access token.
    """
    revoke_all_user_tokens(user["user_id"])
    logger.info("User logged out from all devices: %s", user["sub"])
    return {"message": "Logged out from all devices."}


# ── Me ────────────────────────────────────────────────────────────

@router.get("/me", response_model=MeResponse)
def get_me(user: dict = Depends(verify_token)):
    """
    Return the authenticated user's profile from the token payload.
    No DB lookup required — all info is embedded in the JWT.
    """
    from datetime import datetime
    issued_at  = datetime.fromtimestamp(user["iat"], tz=timezone.utc).isoformat() if "iat" in user else None
    expires_at = datetime.fromtimestamp(user["exp"], tz=timezone.utc).isoformat() if "exp" in user else None
    return MeResponse(
        user_id=user["user_id"],
        username=user["sub"],
        role=user["role"],
        issued_at=issued_at,
        expires_at=expires_at,
    )


# ── Admin: User Management ────────────────────────────────────────

@router.get("/users", response_model=list[UserResponse])
def get_users(admin: dict = Depends(require_role("admin"))):
    """
    List all registered users. Requires admin role.
    Password hashes are never included in the response.
    """
    users = list_users()
    return [
        UserResponse(
            user_id=u["id"],
            username=u["username"],
            role=u["role"],
            is_active=bool(u["is_active"]),
            created_at=u.get("created_at", ""),
        )
        for u in users
    ]


@router.delete("/users/{user_id}", status_code=status.HTTP_200_OK)
def delete_user(user_id: int, admin: dict = Depends(require_role("admin"))):
    """
    Deactivate a user account. Requires admin role.
    This is a soft delete — the account is flagged inactive, not removed.
    Also revokes all their refresh tokens (forces immediate logout).
    """
    if user_id == admin["user_id"]:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="You cannot deactivate your own account.",
        )
    revoke_all_user_tokens(user_id)
    found = deactivate_user(user_id)
    if not found:
        raise HTTPException(status_code=404, detail=f"User {user_id} not found.")
    logger.info("Admin %s deactivated user %d", admin["sub"], user_id)
    return {"message": f"User {user_id} deactivated and all tokens revoked."}
