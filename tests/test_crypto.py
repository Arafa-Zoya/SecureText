
from backend.crypto.hybrid import (
    encrypt_file_data,
    decrypt_file_data
)

from backend.crypto.rsa import (
    generate_key_pair,
    encrypt_message,
    decrypt_message
)


from backend.crypto.classical import (
    caesar_encrypt,
    caesar_decrypt,
    vigenere_encrypt,
    vigenere_decrypt
)

from backend.crypto.key_manager import (
    generate_salt,
    derive_key,
    create_password_key,
    recover_password_key
)

import pytest

from cryptography.exceptions import InvalidTag

from backend.crypto.aes import (
    generate_key,
    encrypt_text,
    decrypt_text,
    encrypt_bytes,
    decrypt_bytes
)


def test_key_generation():
    key = generate_key()

    assert len(key) == 32


def test_text_encryption_decryption():
    key = generate_key()

    original = "Hello! This is my SecureText project."

    encrypted = encrypt_text(original, key)
    decrypted = decrypt_text(encrypted, key)

    assert encrypted != original
    assert decrypted == original


def test_different_ciphertexts():
    key = generate_key()
    message = "Secure information"

    encrypted1 = encrypt_text(message, key)
    encrypted2 = encrypt_text(message, key)

    assert encrypted1 != encrypted2


def test_wrong_key_rejected():
    key1 = generate_key()
    key2 = generate_key()

    encrypted = encrypt_text("Secret message", key1)

    with pytest.raises(InvalidTag):
        decrypt_text(encrypted, key2)


def test_tampering_detected():
    key = generate_key()

    encrypted = encrypt_bytes(b"Confidential data", key)

    tampered = encrypted.copy()
    tampered["ciphertext"] = (
        tampered["ciphertext"][:-4] + "AAAA"
    )

    with pytest.raises((InvalidTag, ValueError)):
        decrypt_bytes(tampered, key)


def test_file_data_encryption():
    key = generate_key()

    original = b"Example file contents for encryption."

    encrypted = encrypt_bytes(original, key)
    decrypted = decrypt_bytes(encrypted, key)

    assert decrypted == original


def test_rsa_key_generation():
    public_key, private_key = generate_key_pair()

    assert public_key.key_size == 2048
    assert private_key.key_size == 2048


def test_rsa_encryption_decryption():
    public_key, private_key = generate_key_pair()

    original = b"SecureText RSA encryption test"

    encrypted = encrypt_message(original, public_key)
    decrypted = decrypt_message(encrypted, private_key)

    assert encrypted != original
    assert decrypted == original


def test_rsa_wrong_private_key():
    public_key1, _ = generate_key_pair()
    _, private_key2 = generate_key_pair()

    encrypted = encrypt_message(
        b"Secret RSA message",
        public_key1
    )

    with pytest.raises(Exception):
        decrypt_message(encrypted, private_key2)


def test_rsa_rejects_large_messages():
    public_key, _ = generate_key_pair()

    large_message = b"A" * 191

    with pytest.raises(ValueError):
        encrypt_message(large_message, public_key)


def test_caesar_encryption_decryption():
    original = "Hello SecureText"
    encrypted = caesar_encrypt(original, 3)
    decrypted = caesar_decrypt(encrypted, 3)

    assert encrypted == "Khoor VhfxuhWhaw"
    assert decrypted == original


def test_caesar_preserves_punctuation():
    original = "Hello, World! 123"
    encrypted = caesar_encrypt(original, 3)

    assert encrypted == "Khoor, Zruog! 123"


def test_vigenere_encryption_decryption():
    original = "ATTACK AT DAWN"
    key = "LEMON"

    encrypted = vigenere_encrypt(original, key)
    decrypted = vigenere_decrypt(encrypted, key)

    assert encrypted == "LXFOPV EF RNHR"
    assert decrypted == original


def test_vigenere_preserves_case_and_punctuation():
    original = "Hello, World!"
    key = "KEY"

    encrypted = vigenere_encrypt(original, key)
    decrypted = vigenere_decrypt(encrypted, key)

    assert decrypted == original


def test_vigenere_rejects_invalid_key():
    with pytest.raises(ValueError):
        vigenere_encrypt("HELLO", "KEY123")


def test_salt_generation():
    salt1 = generate_salt()
    salt2 = generate_salt()

    assert len(salt1) == 16
    assert salt1 != salt2


def test_password_key_derivation():
    salt = generate_salt()
    key = derive_key("MySecurePassword123!", salt)

    assert len(key) == 32


def test_same_password_and_salt_produce_same_key():
    salt = generate_salt()

    key1 = derive_key("SecurePassword123!", salt)
    key2 = derive_key("SecurePassword123!", salt)

    assert key1 == key2


def test_different_salts_produce_different_keys():
    key1 = derive_key("SecurePassword123!", generate_salt())
    key2 = derive_key("SecurePassword123!", generate_salt())

    assert key1 != key2


def test_password_key_recovery():
    password = "MySecurePassword123!"

    key, metadata = create_password_key(password)
    recovered_key = recover_password_key(password, metadata)

    assert key == recovered_key


def test_wrong_password_produces_different_key():
    key, metadata = create_password_key("CorrectPassword123!")
    wrong_key = recover_password_key("WrongPassword123!", metadata)

    assert key != wrong_key


def test_empty_password_rejected():
    salt = generate_salt()

    with pytest.raises(ValueError):
        derive_key("", salt)


def test_hybrid_file_encryption_decryption():
    public_key, private_key = generate_key_pair()

    original = b"This is a confidential file for SecureText."

    encrypted = encrypt_file_data(original, public_key)
    decrypted = decrypt_file_data(encrypted, private_key)

    assert encrypted != original.decode("utf-8")
    assert decrypted == original


def test_hybrid_large_file_encryption():
    public_key, private_key = generate_key_pair()

    original = b"SecureText file content " * 10000

    encrypted = encrypt_file_data(original, public_key)
    decrypted = decrypt_file_data(encrypted, private_key)

    assert decrypted == original


def test_hybrid_wrong_private_key_rejected():
    public_key, _ = generate_key_pair()
    _, wrong_private_key = generate_key_pair()

    encrypted = encrypt_file_data(
        b"Confidential information",
        public_key
    )

    with pytest.raises(ValueError):
        decrypt_file_data(encrypted, wrong_private_key)


def test_hybrid_tampering_detected():
    import json

    public_key, private_key = generate_key_pair()

    encrypted = encrypt_file_data(
        b"Original confidential file",
        public_key
    )

    package = json.loads(encrypted)
    ciphertext = package["file_data"]["ciphertext"]

    package["file_data"]["ciphertext"] = (
        ciphertext[:-4] + "AAAA"
    )

    tampered = json.dumps(package)

    with pytest.raises((ValueError, Exception)):
        decrypt_file_data(tampered, private_key)
