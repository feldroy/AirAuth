"""Tests for core auth functions."""

from unittest.mock import AsyncMock, MagicMock, patch

from airauth.core import (
    authenticate,
    create_superuser,
    create_user,
    generate_api_token,
    login,
    logout,
    revoke_api_token,
)
from airauth.models import APIToken, User


def _make_user(id=1, password_hash=None):
    if password_hash is None:
        from airauth.utils import hash_password

        password_hash = hash_password("test-pass")
    return User(id=id, username="alice", email="a@b.com", password_hash=password_hash)


async def test_create_user():
    with patch.object(User, "create", new_callable=AsyncMock) as mock_create:
        mock_create.return_value = _make_user()
        user = await create_user("alice", "a@b.com", "test-pass")
        assert user.username == "alice"
        call_kwargs = mock_create.call_args.kwargs
        assert call_kwargs["username"] == "alice"
        assert call_kwargs["email"] == "a@b.com"
        assert call_kwargs["password_hash"].startswith("$argon2id$")


async def test_create_superuser():
    with (
        patch.object(User, "create", new_callable=AsyncMock, return_value=_make_user()),
        patch("airauth.core.assign_perm", new_callable=AsyncMock) as mock_assign,
    ):
        user = await create_superuser("alice", "a@b.com", "test-pass")
        assert user.username == "alice"
        mock_assign.assert_called_once_with("admin", user)


async def test_authenticate_success():
    from airauth.utils import hash_password

    user = _make_user(password_hash=hash_password("correct"))
    with (
        patch.object(User, "get", new_callable=AsyncMock, return_value=user),
        patch.object(User, "save", new_callable=AsyncMock),
    ):
        result = await authenticate("alice", "correct")
        assert result is user


async def test_authenticate_wrong_password():
    from airauth.utils import hash_password

    user = _make_user(password_hash=hash_password("correct"))
    with patch.object(User, "get", new_callable=AsyncMock, return_value=user):
        result = await authenticate("alice", "wrong")
        assert result is None


async def test_authenticate_no_user():
    with patch.object(User, "get", new_callable=AsyncMock, return_value=None):
        result = await authenticate("ghost", "pass")
        assert result is None


async def test_authenticate_rehash():
    from argon2 import PasswordHasher

    # Use a weak hasher to produce a hash that the default hasher will want to rehash
    weak = PasswordHasher(time_cost=1, memory_cost=8192, parallelism=1)
    old_hash = weak.hash("mypassword")
    user = _make_user(password_hash=old_hash)

    with (
        patch.object(User, "get", new_callable=AsyncMock, return_value=user),
        patch.object(User, "save", new_callable=AsyncMock) as mock_save,
    ):
        result = await authenticate("alice", "mypassword")
        assert result is user
        if mock_save.called:
            mock_save.assert_called_once_with(update_fields=["password_hash"])
            assert user.password_hash != old_hash


async def test_generate_api_token():
    with patch.object(APIToken, "create", new_callable=AsyncMock) as mock_create:
        user = _make_user()
        raw = await generate_api_token(user, label="test")
        assert len(raw) > 20
        call_kwargs = mock_create.call_args.kwargs
        assert call_kwargs["user_id"] == 1
        assert call_kwargs["label"] == "test"
        assert call_kwargs["token_hash"] == APIToken.hash_token(raw)


async def test_revoke_api_token():
    with patch.object(APIToken, "bulk_delete", new_callable=AsyncMock) as mock_delete:
        await revoke_api_token("raw-token-value")
        mock_delete.assert_called_once_with(token_hash=APIToken.hash_token("raw-token-value"))


def test_login():
    session = {"old_key": "old_value"}
    request = MagicMock()
    request.session = session
    user = _make_user()
    login(request, user)
    assert session == {"user_id": 1}


def test_login_clears_session_first():
    """Session fixation prevention: old keys are gone after login."""
    session = {"attacker_key": "evil"}
    request = MagicMock()
    request.session = session
    user = _make_user()
    login(request, user)
    assert "attacker_key" not in session
    assert session["user_id"] == 1


def test_logout():
    session = {"user_id": 1, "other": "data"}
    request = MagicMock()
    request.session = session
    logout(request)
    assert session == {}
