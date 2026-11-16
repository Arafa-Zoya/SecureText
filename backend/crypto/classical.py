
def caesar_encrypt(message: str, shift: int) -> str:
    """Encrypt text using the Caesar cipher."""
    if not isinstance(message, str):
        raise TypeError("Message must be a string.")
    if not isinstance(shift, int):
        raise TypeError("Shift must be an integer.")

    shift %= 26
    result = []

    for char in message:
        if char.isupper() and char.isascii():
            result.append(chr((ord(char) - ord("A") + shift) % 26 + ord("A")))
        elif char.islower() and char.isascii():
            result.append(chr((ord(char) - ord("a") + shift) % 26 + ord("a")))
        else:
            result.append(char)

    return "".join(result)


def caesar_decrypt(encrypted_message: str, shift: int) -> str:
    """Decrypt text using the Caesar cipher."""
    return caesar_encrypt(encrypted_message, -shift)


def _validate_vigenere_key(key: str) -> str:
    if not isinstance(key, str):
        raise TypeError("Vigenere key must be a string.")

    if not key or not key.isascii() or not key.isalpha():
        raise ValueError("Vigenere key must contain only English letters.")

    return key.upper()


def _vigenere_transform(message: str, key: str, decrypt: bool) -> str:
    if not isinstance(message, str):
        raise TypeError("Message must be a string.")

    key = _validate_vigenere_key(key)
    result = []
    key_index = 0

    for char in message:
        if char.isascii() and char.isalpha():
            shift = ord(key[key_index % len(key)]) - ord("A")

            if decrypt:
                shift = -shift

            base = ord("A") if char.isupper() else ord("a")
            transformed = chr(
                (ord(char) - base + shift) % 26 + base
            )

            result.append(transformed)
            key_index += 1
        else:
            result.append(char)

    return "".join(result)


def vigenere_encrypt(message: str, key: str) -> str:
    """Encrypt text using the Vigenere cipher."""
    return _vigenere_transform(message, key, decrypt=False)


def vigenere_decrypt(encrypted_message: str, key: str) -> str:
    """Decrypt text using the Vigenere cipher."""
    return _vigenere_transform(encrypted_message, key, decrypt=True)
