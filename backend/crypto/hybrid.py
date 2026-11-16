
import json
import base64

from cryptography.hazmat.primitives.asymmetric import rsa

from backend.crypto.aes import generate_key, encrypt_bytes, decrypt_bytes
from backend.crypto.rsa import encrypt_message, decrypt_message


def encrypt_file_data(data: bytes, public_key) -> str:
    """Encrypt file bytes using hybrid AES and RSA encryption."""

    if not isinstance(data, bytes):
        raise TypeError("File data must be bytes.")

    if not isinstance(public_key, rsa.RSAPublicKey):
        raise TypeError("A valid RSA public key is required.")

    # Generate a random AES-256 key.
    aes_key = generate_key()

    # Encrypt the file contents using AES-256-GCM.
    encrypted_file = encrypt_bytes(data, aes_key)

    # Encrypt the AES key using the recipient's RSA public key.
    encrypted_aes_key = encrypt_message(aes_key, public_key)

    # Package the encrypted file and encrypted AES key.
    package = {
        "version": 1,
        "algorithm": "AES-256-GCM+RSA-OAEP-SHA256",
        "encrypted_key": base64.b64encode(
            encrypted_aes_key
        ).decode("utf-8"),
        "file_data": encrypted_file
    }

    return json.dumps(package)


def decrypt_file_data(package_data: str, private_key) -> bytes:
    """Recover the AES key and decrypt the original file."""

    if not isinstance(package_data, str):
        raise TypeError("Encrypted package must be a string.")

    if not isinstance(private_key, rsa.RSAPrivateKey):
        raise TypeError("A valid RSA private key is required.")

    try:
        package = json.loads(package_data)

        if not isinstance(package, dict):
            raise ValueError("Invalid encrypted package.")

        if package.get("version") != 1:
            raise ValueError("Unsupported package version.")

        if package.get("algorithm") != "AES-256-GCM+RSA-OAEP-SHA256":
            raise ValueError("Unsupported encryption algorithm.")

        encrypted_key = base64.b64decode(
            package["encrypted_key"],
            validate=True
        )

        file_data = package["file_data"]

    except (json.JSONDecodeError, KeyError, TypeError, ValueError) as exc:
        raise ValueError("Invalid encrypted package.") from exc

    # Recover the AES key using the recipient's private RSA key.
    aes_key = decrypt_message(encrypted_key, private_key)

    # Authenticate and decrypt the file using AES-GCM.
    return decrypt_bytes(file_data, aes_key)
