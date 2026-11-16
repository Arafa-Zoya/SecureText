
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes


# RSA configuration
KEY_SIZE = 2048
PUBLIC_EXPONENT = 65537


def generate_key_pair():
    """
    Generate an RSA public and private key pair.
    """

    private_key = rsa.generate_private_key(
        public_exponent=PUBLIC_EXPONENT,
        key_size=KEY_SIZE
    )

    public_key = private_key.public_key()

    return public_key, private_key


def encrypt_message(message: bytes, public_key) -> bytes:
    """
    Encrypt a short message using RSA-OAEP with SHA-256.
    """

    if not isinstance(message, bytes):
        raise TypeError("Message must be bytes.")

    if not isinstance(public_key, rsa.RSAPublicKey):
        raise TypeError("A valid RSA public key is required.")

    # Maximum plaintext for RSA-2048 with SHA-256 OAEP is
    # 190 bytes. Use hybrid encryption for larger messages.

    max_length = (
        public_key.key_size // 8
        - 2 * hashes.SHA256().digest_size
        - 2
    )

    if len(message) > max_length:
        raise ValueError(
            f"Message too large for direct RSA encryption. "
            f"Maximum size is {max_length} bytes. "
            "Use hybrid encryption instead."
        )

    ciphertext = public_key.encrypt(
        message,
        padding.OAEP(
            mgf=padding.MGF1(
                algorithm=hashes.SHA256()
            ),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    return ciphertext


def decrypt_message(ciphertext: bytes, private_key) -> bytes:
    """
    Decrypt an RSA-OAEP encrypted message.
    """

    if not isinstance(ciphertext, bytes):
        raise TypeError("Ciphertext must be bytes.")

    if not isinstance(private_key, rsa.RSAPrivateKey):
        raise TypeError("A valid RSA private key is required.")

    if len(ciphertext) != private_key.key_size // 8:
        raise ValueError("Invalid RSA ciphertext length.")

    plaintext = private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(
                algorithm=hashes.SHA256()
            ),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    return plaintext
