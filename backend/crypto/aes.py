
import os
import json
import base64

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


# AES-256 configuration
KEY_SIZE = 32       # 32 bytes = 256 bits
NONCE_SIZE = 12     # 96-bit nonce
ALGORITHM = "AES-256-GCM"
VERSION = 1


def generate_key():
    """
    Generate a cryptographically secure 256-bit AES key.
    """
    return AESGCM.generate_key(bit_length=256)


def encrypt_bytes(data: bytes, key: bytes) -> dict:
    """
    Encrypt bytes using AES-256-GCM.

    Returns a JSON-serializable envelope containing
    the nonce and authenticated ciphertext.
    """

    if not isinstance(data, bytes):
        raise TypeError("Data must be bytes.")

    if len(key) != KEY_SIZE:
        raise ValueError("AES key must be exactly 32 bytes.")

    nonce = os.urandom(NONCE_SIZE)

    aes = AESGCM(key)

    # Additional authenticated data binds the format
    aad = f"SecureText:{VERSION}:{ALGORITHM}".encode()

    ciphertext = aes.encrypt(nonce, data, aad)

    return {
        "version": VERSION,
        "algorithm": ALGORITHM,
        "nonce": base64.b64encode(nonce).decode("utf-8"),
        "ciphertext": base64.b64encode(ciphertext).decode("utf-8")
    }


def decrypt_bytes(envelope: dict, key: bytes) -> bytes:
    """
    Decrypt and authenticate AES-256-GCM ciphertext.
    """

    if not isinstance(key, bytes) or len(key) != KEY_SIZE:
        raise ValueError("Invalid AES-256 key.")

    if not isinstance(envelope, dict):
        raise ValueError("Invalid encrypted data format.")

    if envelope.get("version") != VERSION:
        raise ValueError("Unsupported encrypted data version.")

    if envelope.get("algorithm") != ALGORITHM:
        raise ValueError("Unsupported encryption algorithm.")

    try:
        nonce = base64.b64decode(
            envelope["nonce"], validate=True
        )

        ciphertext = base64.b64decode(
            envelope["ciphertext"], validate=True
        )

    except (KeyError, ValueError, TypeError) as exc:
        raise ValueError("Invalid encrypted data format.") from exc

    if len(nonce) != NONCE_SIZE:
        raise ValueError("Invalid AES nonce.")

    aad = f"SecureText:{VERSION}:{ALGORITHM}".encode()

    aes = AESGCM(key)

    # Authentication failure raises InvalidTag.
    return aes.decrypt(nonce, ciphertext, aad)


def encrypt_text(message: str, key: bytes) -> str:
    """
    Encrypt a UTF-8 text message.
    """

    if not isinstance(message, str):
        raise TypeError("Message must be a string.")

    envelope = encrypt_bytes(message.encode("utf-8"), key)

    return json.dumps(envelope)


def decrypt_text(encrypted_message: str, key: bytes) -> str:
    """
    Decrypt an encrypted UTF-8 text message.
    """

    try:
        envelope = json.loads(encrypted_message)
    except (json.JSONDecodeError, TypeError) as exc:
        raise ValueError("Invalid encrypted message.") from exc

    decrypted = decrypt_bytes(envelope, key)

    return decrypted.decode("utf-8")
