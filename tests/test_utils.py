"""Tests for password hashing utilities."""

from airauth.utils import _DUMMY_HASH, hash_password, needs_rehash, verify_password


def test_hash_produces_argon2id():
    h = hash_password("test-password")
    assert h.startswith("$argon2id$")


def test_verify_correct_password():
    h = hash_password("correct-horse-battery-staple")
    assert verify_password("correct-horse-battery-staple", h) is True


def test_verify_wrong_password():
    h = hash_password("correct-horse-battery-staple")
    assert verify_password("wrong-password", h) is False


def test_verify_corrupt_hash_returns_false():
    assert verify_password("anything", "not-a-valid-hash") is False


def test_fresh_hash_does_not_need_rehash():
    h = hash_password("test-password")
    assert needs_rehash(h) is False


def test_dummy_hash_is_argon2id():
    assert _DUMMY_HASH.startswith("$argon2id$")


def test_different_passwords_produce_different_hashes():
    h1 = hash_password("password-one")
    h2 = hash_password("password-two")
    assert h1 != h2


def test_same_password_produces_different_hashes():
    """Argon2 uses random salt, so same input gives different output."""
    h1 = hash_password("same-password")
    h2 = hash_password("same-password")
    assert h1 != h2
