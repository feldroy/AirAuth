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

    Middleware ordering (LIFO in Starlette):
    - AuthMiddleware (outermost, runs first on request)
    - SessionMiddleware (innermost, runs last on request, first on response)

    Skips SessionMiddleware if already registered (e.g. by the app).
    """
    if not _has_middleware(app, SessionMiddleware):
        app.add_middleware(SessionMiddleware, secret_key=secret_key)
    app.add_middleware(AuthMiddleware)
