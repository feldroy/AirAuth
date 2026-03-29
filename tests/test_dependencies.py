"""Tests for FastAPI auth dependencies."""

from datetime import UTC, datetime
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi import HTTPException

from airauth.dependencies import _current_user, _require_login, _require_token
from airauth.models import APIToken, User


def _make_user(id=1):
    return User(id=id, username="alice", email="a@b.com", password_hash="h")


def _make_request(user=None):
    request = MagicMock()
    request.state.user = user
    return request


def test_current_user_returns_user():
    user = _make_user()
    request = _make_request(user)
    assert _current_user(request) is user


def test_current_user_returns_none():
    request = _make_request(None)
    assert _current_user(request) is None


def test_current_user_no_state_attr():
    """When request.state has no user attribute, return None."""
    request = MagicMock()
    request.state = MagicMock(spec=[])
    assert _current_user(request) is None


def test_require_login_returns_user():
    user = _make_user()
    request = _make_request(user)
    assert _require_login(request) is user


def test_require_login_raises_on_no_user():
    request = _make_request(None)
    with pytest.raises(HTTPException) as exc_info:
        _require_login(request)
    assert exc_info.value.status_code == 303


async def test_require_token_valid():
    user = _make_user()
    token_obj = APIToken(
        id=1,
        user_id=1,
        token_hash=APIToken.hash_token("raw-token"),
        created_at=datetime.now(UTC),
    )
    with (
        patch.object(APIToken, "get", new_callable=AsyncMock, return_value=token_obj),
        patch.object(User, "get", new_callable=AsyncMock, return_value=user),
        patch.object(APIToken, "save", new_callable=AsyncMock),
    ):
        result = await _require_token(token="raw-token")
        assert result is user


async def test_require_token_no_token():
    with pytest.raises(HTTPException) as exc_info:
        await _require_token(token=None)
    assert exc_info.value.status_code == 401


async def test_require_token_invalid():
    with patch.object(APIToken, "get", new_callable=AsyncMock, return_value=None):
        with pytest.raises(HTTPException) as exc_info:
            await _require_token(token="bad-token")
        assert exc_info.value.status_code == 401


async def test_require_token_inactive_user():
    token_obj = APIToken(
        id=1,
        user_id=1,
        token_hash=APIToken.hash_token("raw-token"),
        created_at=datetime.now(UTC),
    )
    with (
        patch.object(APIToken, "get", new_callable=AsyncMock, return_value=token_obj),
        patch.object(User, "get", new_callable=AsyncMock, return_value=None),
    ):
        with pytest.raises(HTTPException) as exc_info:
            await _require_token(token="raw-token")
        assert exc_info.value.status_code == 401


async def test_require_token_updates_last_used():
    user = _make_user()
    token_obj = APIToken(
        id=1,
        user_id=1,
        token_hash=APIToken.hash_token("raw-token"),
        created_at=datetime.now(UTC),
    )
    with (
        patch.object(APIToken, "get", new_callable=AsyncMock, return_value=token_obj),
        patch.object(User, "get", new_callable=AsyncMock, return_value=user),
        patch.object(APIToken, "save", new_callable=AsyncMock) as mock_save,
    ):
        await _require_token(token="raw-token")
        mock_save.assert_called_once_with(update_fields=["last_used_at"])
        assert token_obj.last_used_at is not None
