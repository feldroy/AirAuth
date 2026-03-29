"""Auth middleware for loading the current user from session."""

from starlette.types import ASGIApp, Receive, Scope, Send

from .models import User


class AuthMiddleware:
    """Load the current user from session on every request.

    After this middleware runs, scope["state"]["user"] is either
    a User instance or None.
    """

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] in ("http", "websocket"):
            state = scope.setdefault("state", {})
            session = scope.get("session", {})
            user_id = session.get("user_id")
            if user_id:
                state["user"] = await User.get(id=user_id, is_active=True)
            else:
                state["user"] = None
        await self.app(scope, receive, send)
