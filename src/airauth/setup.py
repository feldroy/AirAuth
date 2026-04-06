"""App setup helper for wiring auth middleware."""

from starlette.middleware.sessions import SessionMiddleware

from .middleware import AuthMiddleware


def _has_middleware(app, cls) -> bool:
    """Check if middleware is already registered on the app."""
    for mw in getattr(app, "user_middleware", []):
        if mw.cls is cls:
            return True
    return False


def init_auth(app, secret_key: str) -> None:
    """Wire up session + auth middleware in the correct order.

    Starlette middleware is LIFO: the LAST added runs FIRST on request.
    AuthMiddleware needs the session to be decoded already, so
    SessionMiddleware must run before it (i.e., be added AFTER it).

    Add order: AuthMiddleware first, then SessionMiddleware.
    Request order: SessionMiddleware decodes cookie, AuthMiddleware reads it.
    """
    app.add_middleware(AuthMiddleware)
    if not _has_middleware(app, SessionMiddleware):
        app.add_middleware(SessionMiddleware, secret_key=secret_key)
