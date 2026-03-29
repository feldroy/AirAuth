"""Tests for AirAuth models."""

from unittest.mock import AsyncMock, patch

from airauth.models import _GLOBAL, APIToken, User, UserPermission


def test_user_table_name():
    assert User._table_name() == "airauth_user"


def test_user_permission_table_name():
    assert UserPermission._table_name() == "airauth_user_permission"


def test_api_token_table_name():
    assert APIToken._table_name() == "airauth_api_token"


def test_api_token_hash_is_sha256_hex():
    h = APIToken.hash_token("test-token")
    assert len(h) == 64
    assert all(c in "0123456789abcdef" for c in h)


def test_api_token_hash_deterministic():
    assert APIToken.hash_token("same") == APIToken.hash_token("same")


def test_api_token_hash_different_inputs():
    assert APIToken.hash_token("a") != APIToken.hash_token("b")


def test_user_defaults():
    user = User(username="alice", email="alice@example.com", password_hash="$argon2id$hash")
    assert user.id is None
    assert user.is_active is True
    assert user.last_login is None
    assert user.date_joined is not None


def test_user_permission_global_defaults():
    perm = UserPermission(user_id=1, permission="admin")
    assert perm.object_type == _GLOBAL
    assert perm.object_id == _GLOBAL


async def test_has_perm_global():
    user = User(id=1, username="alice", email="a@b.com", password_hash="h")
    with patch.object(UserPermission, "count", new_callable=AsyncMock, return_value=1):
        assert await user.has_perm("admin") is True


async def test_has_perm_global_denied():
    user = User(id=1, username="alice", email="a@b.com", password_hash="h")
    with patch.object(UserPermission, "count", new_callable=AsyncMock, return_value=0):
        assert await user.has_perm("admin") is False


async def test_has_perm_object():
    user = User(id=1, username="alice", email="a@b.com", password_hash="h")

    class FakeObj:
        id = 42

        class __class_with_table:
            pass

    fake = FakeObj()
    fake.__class__ = type("FakeModel", (), {"_table_name": classmethod(lambda cls: "app_post"), "id": 42})
    fake.id = 42

    with patch.object(UserPermission, "count", new_callable=AsyncMock, return_value=1) as mock_count:
        result = await user.has_perm("edit", fake)
        assert result is True
        mock_count.assert_called_once_with(
            user_id=1,
            permission="edit",
            object_type="app_post",
            object_id="42",
        )
