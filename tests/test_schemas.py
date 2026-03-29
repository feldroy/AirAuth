"""Tests for Pydantic schemas."""

import pytest
from pydantic import ValidationError

from airauth.schemas import UserCreate, UserLogin, UserRead


def test_user_create_valid():
    u = UserCreate(username="alice", email="alice@example.com", password="strongpass")
    assert u.username == "alice"


def test_user_create_short_username():
    with pytest.raises(ValidationError):
        UserCreate(username="ab", email="a@b.com", password="strongpass")


def test_user_create_short_password():
    with pytest.raises(ValidationError):
        UserCreate(username="alice", email="a@b.com", password="short")


def test_user_login_valid():
    u = UserLogin(username="alice", password="anything")
    assert u.username == "alice"


def test_user_read_valid():
    u = UserRead(id=1, username="alice", email="a@b.com", is_active=True)
    assert u.id == 1


def test_user_read_no_password_hash_field():
    assert "password_hash" not in UserRead.model_fields


def test_user_create_no_id_field():
    assert "id" not in UserCreate.model_fields


def test_user_login_no_email_field():
    assert "email" not in UserLogin.model_fields
