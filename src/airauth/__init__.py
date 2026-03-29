"""AirAuth: Secure authentication for Air web framework sites."""

from .core import authenticate, create_superuser, create_user, generate_api_token, login, logout, revoke_api_token
from .dependencies import current_user, require_login, require_object_perm, require_perm, require_token
from .middleware import AuthMiddleware
from .models import APIToken, User, UserPermission
from .permissions import assign_perm, get_objects_for_user, get_users_with_perm, remove_perm
from .setup import init_auth
from .utils import hash_password, needs_rehash, verify_password

__all__ = [
    "APIToken",
    "AuthMiddleware",
    "User",
    "UserPermission",
    "assign_perm",
    "authenticate",
    "create_superuser",
    "create_user",
    "current_user",
    "generate_api_token",
    "get_objects_for_user",
    "get_users_with_perm",
    "hash_password",
    "init_auth",
    "login",
    "logout",
    "needs_rehash",
    "remove_perm",
    "require_login",
    "require_object_perm",
    "require_perm",
    "require_token",
    "revoke_api_token",
    "verify_password",
]
