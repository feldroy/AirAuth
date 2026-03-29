"""Tests for AuthMiddleware."""

from unittest.mock import AsyncMock, patch

from airauth.middleware import AuthMiddleware
from airauth.models import User


def _make_user(id=1):
    return User(id=id, username="alice", email="a@b.com", password_hash="h")


async def test_middleware_loads_user_from_session():
    user = _make_user()
    captured_state = {}

    async def downstream(scope, receive, send):
        captured_state.update(scope["state"])

    app = AuthMiddleware(downstream)
    scope = {"type": "http", "session": {"user_id": 1}, "state": {}}

    with patch.object(User, "get", new_callable=AsyncMock, return_value=user):
        await app(scope, AsyncMock(), AsyncMock())

    assert captured_state["user"] is user


async def test_middleware_no_session():
    captured_state = {}

    async def downstream(scope, receive, send):
        captured_state.update(scope["state"])

    app = AuthMiddleware(downstream)
    scope = {"type": "http", "session": {}, "state": {}}

    await app(scope, AsyncMock(), AsyncMock())
    assert captured_state["user"] is None


async def test_middleware_no_user_id_in_session():
    captured_state = {}

    async def downstream(scope, receive, send):
        captured_state.update(scope["state"])

    app = AuthMiddleware(downstream)
    scope = {"type": "http", "session": {"other": "data"}, "state": {}}

    await app(scope, AsyncMock(), AsyncMock())
    assert captured_state["user"] is None


async def test_middleware_creates_state_dict():
    """scope["state"] may not exist; middleware creates it."""
    captured = {}

    async def downstream(scope, receive, send):
        captured.update(scope["state"])

    app = AuthMiddleware(downstream)
    scope = {"type": "http", "session": {}}

    await app(scope, AsyncMock(), AsyncMock())
    assert "state" in scope
    assert captured["user"] is None


async def test_middleware_skips_lifespan():
    called = False

    async def downstream(scope, receive, send):
        nonlocal called
        called = True

    app = AuthMiddleware(downstream)
    scope = {"type": "lifespan"}

    await app(scope, AsyncMock(), AsyncMock())
    assert called
    assert "state" not in scope


async def test_middleware_inactive_user_returns_none():
    """User.get with is_active=True returns None for inactive users."""
    captured_state = {}

    async def downstream(scope, receive, send):
        captured_state.update(scope["state"])

    app = AuthMiddleware(downstream)
    scope = {"type": "http", "session": {"user_id": 1}, "state": {}}

    with patch.object(User, "get", new_callable=AsyncMock, return_value=None):
        await app(scope, AsyncMock(), AsyncMock())

    assert captured_state["user"] is None
