"""Tests for init_auth setup helper."""

from unittest.mock import MagicMock, call

from starlette.middleware.sessions import SessionMiddleware

from airauth.middleware import AuthMiddleware
from airauth.setup import init_auth


def test_init_auth_adds_middleware():
    app = MagicMock()
    init_auth(app, secret_key="test-secret")
    assert app.add_middleware.call_count == 2


def test_init_auth_middleware_order():
    """AuthMiddleware added first, SessionMiddleware second.

    Starlette middleware is LIFO: the last added runs first on request.
    SessionMiddleware must run first to decode the cookie before
    AuthMiddleware reads the session.
    """
    app = MagicMock()
    init_auth(app, secret_key="test-secret")
    calls = app.add_middleware.call_args_list
    assert calls[0] == call(AuthMiddleware)
    assert calls[1] == call(SessionMiddleware, secret_key="test-secret")
