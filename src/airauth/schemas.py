"""Pydantic schemas for auth input/output validation.

These are plain BaseModel subclasses (not AirModel) to avoid registering
phantom tables via AirModel.__init_subclass__.
"""

from air import AirField
from pydantic import BaseModel


class UserCreate(BaseModel):
    username: str = AirField(min_length=3, max_length=150)
    email: str = AirField(type="email")
    password: str = AirField(type="password", min_length=8)


class UserLogin(BaseModel):
    username: str = AirField(autofocus=True)
    password: str = AirField(type="password")


class UserRead(BaseModel):
    """Public-facing user data. No password hash, no tokens."""

    id: int
    username: str
    email: str
    is_active: bool
