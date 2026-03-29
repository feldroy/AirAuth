"""FastAPI dependencies for auth.

Pre-wrapped Depends() objects following Air's is_htmx_request pattern.
"""

from datetime import UTC, datetime

from fastapi import Depends, HTTPException
from fastapi.security import OAuth2PasswordBearer
from starlette.requests import Request

from .models import APIToken, User

_oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/token", auto_error=False)


# --- Identity (who is this?) ---


def _current_user(request: Request) -> User | None:
    return getattr(request.state, "user", None)


current_user = Depends(_current_user)


def _require_login(request: Request) -> User:
    user = getattr(request.state, "user", None)
    if not user:
        raise HTTPException(status_code=303, headers={"Location": "/login"})
    return user


require_login = Depends(_require_login)


async def _require_token(token: str = Depends(_oauth2_scheme)) -> User:
    if not token:
        raise HTTPException(status_code=401, detail="Not authenticated")
    token_obj = await APIToken.get(token_hash=APIToken.hash_token(token))
    if not token_obj:
        raise HTTPException(status_code=401, detail="Invalid token")
    user = await User.get(id=token_obj.user_id, is_active=True)
    if not user:
        raise HTTPException(status_code=401, detail="Invalid token")
    token_obj.last_used_at = datetime.now(UTC)
    await token_obj.save(update_fields=["last_used_at"])
    return user


require_token = Depends(_require_token)


# --- Authorization (can they do this?) ---


def require_perm(perm: str):
    """Dependency that checks a global permission."""

    async def _check(request: Request) -> User:
        user = _require_login(request)
        if not await user.has_perm(perm):
            raise HTTPException(status_code=403)
        return user

    return Depends(_check)


def require_object_perm(perm: str, obj_getter):
    """Dependency that checks an object-level permission.

    Returns a (user, obj) tuple so the route handler gets both
    without fetching the object a second time.
    """

    async def _check(request: Request) -> tuple[User, object]:
        user = _require_login(request)
        obj = await obj_getter(request)
        if not await user.has_perm(perm, obj):
            raise HTTPException(status_code=403)
        return user, obj

    return Depends(_check)
