"""Core authentication functions.

User creation, credential verification, session login/logout, API token management.
"""

import secrets

from .models import APIToken, User
from .permissions import assign_perm
from .utils import _DUMMY_HASH, hash_password, needs_rehash, verify_password


async def create_user(username: str, email: str, password: str = "") -> User:
    """Create a user with a hashed password.

    If password is empty, the user cannot log in via password auth
    (useful for OAuth-only accounts that may set a password later).
    """
    return await User.create(
        username=username,
        email=email,
        password_hash=hash_password(password) if password else "",
    )


async def create_superuser(username: str, email: str, password: str) -> User:
    """Create a user and grant the 'admin' global permission.

    'admin' is a convention, not a framework-level concept.
    """
    user = await create_user(username, email, password)
    await assign_perm("admin", user)
    return user


async def authenticate(username: str, password: str) -> User | None:
    """Verify credentials. Returns the user or None.

    Timing-safe: when the user doesn't exist, a dummy hash is verified
    so response time is indistinguishable from a wrong-password attempt.
    """
    user = await User.get(username=username, is_active=True)
    if user is None:
        verify_password(password, _DUMMY_HASH)
        return None
    if not verify_password(password, user.password_hash):
        return None
    if needs_rehash(user.password_hash):
        user.password_hash = hash_password(password)
        await user.save(update_fields=["password_hash"])
    return user


async def generate_api_token(user: User, label: str = "") -> str:
    """Generate a bearer token for API auth.

    Returns the raw token (display it once, it's never stored).
    """
    raw_token = secrets.token_urlsafe(32)
    await APIToken.create(
        user_id=user.id,
        token_hash=APIToken.hash_token(raw_token),
        label=label,
    )
    return raw_token


async def revoke_api_token(token: str) -> None:
    """Revoke an API token by its raw value."""
    await APIToken.bulk_delete(token_hash=APIToken.hash_token(token))


def login(request, user: User) -> None:
    """Store user ID in session. Clears first to prevent session fixation."""
    request.session.clear()
    request.session["user_id"] = user.id


def logout(request) -> None:
    """Clear session."""
    request.session.clear()
