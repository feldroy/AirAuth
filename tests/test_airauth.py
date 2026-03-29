"""Smoke tests for the airauth package."""

import airauth


def test_import():
    """Verify the package can be imported."""
    assert airauth


def test_public_api():
    """Verify all expected names are exported."""
    expected = {
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
    }
    assert expected == set(airauth.__all__)
