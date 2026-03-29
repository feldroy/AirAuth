"""Management CLI for AirAuth.

Provides commands for creating users and superusers,
like Django's createsuperuser management command.
"""

import asyncio

import typer
from rich.console import Console

app = typer.Typer(help="AirAuth management commands.")
console = Console()


@app.command()
def create_user(
    username: str = typer.Option(..., prompt=True),
    email: str = typer.Option(..., prompt=True),
    password: str = typer.Option(..., prompt=True, hide_input=True, confirmation_prompt=True),
) -> None:
    """Create a new user."""
    from .core import create_user as _create_user

    user = asyncio.run(_create_user(username, email, password))
    console.print(f"Created user {user.username} (id={user.id})")


@app.command()
def create_superuser(
    username: str = typer.Option(..., prompt=True),
    email: str = typer.Option(..., prompt=True),
    password: str = typer.Option(..., prompt=True, hide_input=True, confirmation_prompt=True),
) -> None:
    """Create a new user with the 'admin' global permission."""
    from .core import create_superuser as _create_superuser

    user = asyncio.run(_create_superuser(username, email, password))
    console.print(f"Created superuser {user.username} (id={user.id})")


if __name__ == "__main__":
    app()
