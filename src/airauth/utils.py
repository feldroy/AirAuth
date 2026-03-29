"""Password hashing utilities for AirAuth.

Pure functions, no model dependencies. Uses argon2id via argon2-cffi.
"""

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError

_hasher = PasswordHasher()

# Pre-computed hash for timing-safe authentication.
# When a user doesn't exist, we still run verification against this
# so the response time is indistinguishable from a wrong-password attempt.
_DUMMY_HASH = _hasher.hash("air-auth-dummy-password-for-timing-safety")


def hash_password(password: str) -> str:
    """Hash a password with argon2id."""
    return _hasher.hash(password)


def verify_password(password: str, password_hash: str) -> bool:
    """Verify a password against its hash.

    Returns False for wrong passwords and corrupt hashes alike,
    so a bad row in the database never causes a 500.
    """
    try:
        return _hasher.verify(password_hash, password)
    except (VerificationError, InvalidHashError):
        return False


def needs_rehash(password_hash: str) -> bool:
    """Check if a hash should be re-computed with current parameters."""
    return _hasher.check_needs_rehash(password_hash)
