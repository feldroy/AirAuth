"""AirAuth database models.

Three AirModel subclasses for users, permissions, and API tokens.
Table names: airauth_user, airauth_user_permission, airauth_api_token.
"""

import hashlib
from datetime import UTC, datetime

from air import AirField, AirModel

# Sentinel for global permissions (avoids NULL comparison issues in SQL)
_GLOBAL = ""


class User(AirModel):
    id: int | None = AirField(default=None, primary_key=True)
    username: str
    email: str
    password_hash: str = AirField(default="")
    is_active: bool = AirField(default=True)
    date_joined: datetime = AirField(default_factory=lambda: datetime.now(UTC))
    last_login: datetime | None = None

    async def has_perm(self, perm: str, obj=None) -> bool:
        """Check if this user has a permission, optionally on a specific object."""
        if obj is not None:
            obj_type = obj.__class__._table_name()
            obj_id = str(obj.id)
        else:
            obj_type = _GLOBAL
            obj_id = _GLOBAL
        return (
            await UserPermission.count(
                user_id=self.id,
                permission=perm,
                object_type=obj_type,
                object_id=obj_id,
            )
            > 0
        )


class UserPermission(AirModel):
    """Object-level permissions. Inspired by django-guardian.

    Global permissions: object_type and object_id are both empty string.
    Object permissions: object_type is the AirModel table name,
    object_id is str(pk) to support both integer and UUID primary keys.
    """

    id: int | None = AirField(default=None, primary_key=True)
    user_id: int
    permission: str
    object_type: str = AirField(default=_GLOBAL)
    object_id: str = AirField(default=_GLOBAL)


class APIToken(AirModel):
    """Bearer tokens for API auth. Stored as SHA-256 hashes.

    The raw token is returned only at generation time and never stored.
    Lookup: hash the incoming bearer token and compare against token_hash.
    """

    id: int | None = AirField(default=None, primary_key=True)
    user_id: int
    token_hash: str
    label: str = AirField(default="")
    created_at: datetime = AirField(default_factory=lambda: datetime.now(UTC))
    last_used_at: datetime | None = None

    @staticmethod
    def hash_token(token: str) -> str:
        return hashlib.sha256(token.encode()).hexdigest()
