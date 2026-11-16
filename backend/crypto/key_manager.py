
import os
import base64

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

KEY_LENGTH = 32
SALT_LENGTH = 16
ITERATIONS = 600_000
ALGORITHM = "PBKDF2-HMAC-SHA256"


def generate_salt() -> bytes:
    """Generate a cryptographically secure random salt."""
    return os.urandom(SALT_LENGTH)


def derive_key(password: str, salt: bytes,
               iterations: int = ITERATIONS) -> bytes:
    """Derive a 256-bit encryption key from a password."""
    if not isinstance(password, str) or not password:
        raise ValueError("Password must be a non-empty string.")

    if not isinstance(salt, bytes) or len(salt) != SALT_LENGTH:
        raise ValueError("Salt must be exactly 16 bytes.")

    if (not isinstance(iterations, int) or isinstance(iterations, bool)
            or iterations < 100_000):
        raise ValueError("Invalid iteration count.")

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_LENGTH,
        salt=salt,
        iterations=iterations
    )

    return kdf.derive(password.encode("utf-8"))


def create_password_key(password: str) -> tuple:
    """Create a new password-derived key and its public metadata."""
    salt = generate_salt()
    key = derive_key(password, salt)

    metadata = {
        "algorithm": ALGORITHM,
        "salt": base64.b64encode(salt).decode("utf-8"),
        "iterations": ITERATIONS
    }

    return key, metadata


def recover_password_key(password: str, metadata: dict) -> bytes:
    """Re-derive the original key using its saved metadata."""
    if not isinstance(metadata, dict):
        raise ValueError("Invalid key metadata.")

    if metadata.get("algorithm") != ALGORITHM:
        raise ValueError("Unsupported key derivation algorithm.")

    try:
        salt = base64.b64decode(metadata["salt"], validate=True)
        iterations = metadata["iterations"]
    except (KeyError, ValueError, TypeError) as exc:
        raise ValueError("Invalid key metadata.") from exc

    return derive_key(password, salt, iterations)
