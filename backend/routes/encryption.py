
import base64

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import (
    BestAvailableEncryption
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

from flask import Blueprint, request, jsonify
from cryptography.exceptions import InvalidTag

from backend.crypto.aes import encrypt_text, decrypt_text
from backend.crypto.key_manager import (
    create_password_key,
    recover_password_key
)

encryption_bp = Blueprint("encryption", __name__)

MAX_MESSAGE_LENGTH = 1_000_000


def get_request_data():
    data = request.get_json(silent=True)

    if not isinstance(data, dict):
        return None

    return data


@encryption_bp.route("/encrypt", methods=["POST"])
def encrypt():
    data = get_request_data()

    if data is None:
        return jsonify({"error": "A valid JSON request is required."}), 400

    message = data.get("message")
    password = data.get("password")

    if not isinstance(message, str) or not message:
        return jsonify({"error": "Message cannot be empty."}), 400

    if len(message) > MAX_MESSAGE_LENGTH:
        return jsonify({"error": "Message is too large."}), 413

    if not isinstance(password, str) or not password:
        return jsonify({"error": "A password is required."}), 400

    try:
        key, key_metadata = create_password_key(password)
        encrypted_data = encrypt_text(message, key)

        return jsonify({
            "success": True,
            "algorithm": "AES-256-GCM",
            "encrypted_data": encrypted_data,
            "key_metadata": key_metadata
        }), 200

    except (ValueError, TypeError):
        return jsonify({"error": "Unable to encrypt the message."}), 400


@encryption_bp.route("/decrypt", methods=["POST"])
def decrypt():
    data = get_request_data()

    if data is None:
        return jsonify({"error": "A valid JSON request is required."}), 400

    encrypted_data = data.get("encrypted_data")
    key_metadata = data.get("key_metadata")
    password = data.get("password")

    if not isinstance(encrypted_data, str) or not encrypted_data:
        return jsonify({"error": "Encrypted data is required."}), 400

    if len(encrypted_data) > MAX_MESSAGE_LENGTH * 2:
        return jsonify({"error": "Encrypted data is too large."}), 413

    if not isinstance(password, str) or not password:
        return jsonify({"error": "A password is required."}), 400

    try:
        key = recover_password_key(password, key_metadata)
        decrypted_message = decrypt_text(encrypted_data, key)

        return jsonify({
            "success": True,
            "algorithm": "AES-256-GCM",
            "decrypted_message": decrypted_message
        }), 200

    except (InvalidTag, ValueError, TypeError, UnicodeDecodeError):
        return jsonify({
            "error": "Decryption failed. Check your password and encrypted data."
        }), 400


# --------------------------------------------------
# CAESAR CIPHER API
# --------------------------------------------------

@encryption_bp.route("/caesar/encrypt", methods=["POST"])
def caesar_encrypt_api():
    data = get_request_data()

    if data is None:
        return jsonify({"error": "Valid JSON is required."}), 400

    message = data.get("message")
    shift = data.get("shift")

    if not isinstance(message, str):
        return jsonify({"error": "Message must be text."}), 400

    if not isinstance(shift, int) or isinstance(shift, bool):
        return jsonify({"error": "Shift must be an integer."}), 400

    if len(message) > MAX_MESSAGE_LENGTH:
        return jsonify({"error": "Message is too large."}), 413

    try:
        result = caesar_encrypt(message, shift)

        return jsonify({
            "success": True,
            "algorithm": "Caesar Cipher",
            "encrypted_message": result
        }), 200

    except (ValueError, TypeError):
        return jsonify({"error": "Caesar encryption failed."}), 400


@encryption_bp.route("/caesar/decrypt", methods=["POST"])
def caesar_decrypt_api():
    data = get_request_data()

    if data is None:
        return jsonify({"error": "Valid JSON is required."}), 400

    message = data.get("message")
    shift = data.get("shift")

    if not isinstance(message, str):
        return jsonify({"error": "Message must be text."}), 400

    if not isinstance(shift, int) or isinstance(shift, bool):
        return jsonify({"error": "Shift must be an integer."}), 400

    if len(message) > MAX_MESSAGE_LENGTH:
        return jsonify({"error": "Message is too large."}), 413

    try:
        result = caesar_decrypt(message, shift)

        return jsonify({
            "success": True,
            "algorithm": "Caesar Cipher",
            "decrypted_message": result
        }), 200

    except (ValueError, TypeError):
        return jsonify({"error": "Caesar decryption failed."}), 400


# --------------------------------------------------
# VIGENERE CIPHER API
# --------------------------------------------------

@encryption_bp.route("/vigenere/encrypt", methods=["POST"])
def vigenere_encrypt_api():
    data = get_request_data()

    if data is None:
        return jsonify({"error": "Valid JSON is required."}), 400

    message = data.get("message")
    key = data.get("key")

    if not isinstance(message, str):
        return jsonify({"error": "Message must be text."}), 400

    if not isinstance(key, str):
        return jsonify({"error": "A valid key is required."}), 400

    if len(message) > MAX_MESSAGE_LENGTH:
        return jsonify({"error": "Message is too large."}), 413

    try:
        result = vigenere_encrypt(message, key)

        return jsonify({
            "success": True,
            "algorithm": "Vigenere Cipher",
            "encrypted_message": result
        }), 200

    except (ValueError, TypeError):
        return jsonify({"error": "Invalid Vigenere key or message."}), 400


@encryption_bp.route("/vigenere/decrypt", methods=["POST"])
def vigenere_decrypt_api():
    data = get_request_data()

    if data is None:
        return jsonify({"error": "Valid JSON is required."}), 400

    message = data.get("message")
    key = data.get("key")

    if not isinstance(message, str):
        return jsonify({"error": "Message must be text."}), 400

    if not isinstance(key, str):
        return jsonify({"error": "A valid key is required."}), 400

    if len(message) > MAX_MESSAGE_LENGTH:
        return jsonify({"error": "Message is too large."}), 413

    try:
        result = vigenere_decrypt(message, key)

        return jsonify({
            "success": True,
            "algorithm": "Vigenere Cipher",
            "decrypted_message": result
        }), 200

    except (ValueError, TypeError):
        return jsonify({"error": "Invalid Vigenere key or message."}), 400


# --------------------------------------------------
# RSA KEY GENERATION API
# --------------------------------------------------

@encryption_bp.route("/rsa/keys", methods=["POST"])
def rsa_generate_keys_api():
    data = get_request_data()

    if data is None:
        return jsonify({"error": "Valid JSON is required."}), 400

    password = data.get("password")

    if not isinstance(password, str) or len(password) < 12:
        return jsonify({
            "error": "Private key password must contain at least 12 characters."
        }), 400

    try:
        public_key, private_key = generate_key_pair()

        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

        encrypted_private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=BestAvailableEncryption(
                password.encode("utf-8")
            )
        )

        return jsonify({
            "success": True,
            "algorithm": "RSA-2048-OAEP-SHA256",
            "public_key": public_pem.decode("utf-8"),
            "encrypted_private_key": encrypted_private_pem.decode("utf-8")
        }), 200

    except (ValueError, TypeError):
        return jsonify({"error": "RSA key generation failed."}), 400


# --------------------------------------------------
# RSA ENCRYPTION API
# --------------------------------------------------

@encryption_bp.route("/rsa/encrypt", methods=["POST"])
def rsa_encrypt_api():
    data = get_request_data()

    if data is None:
        return jsonify({"error": "Valid JSON is required."}), 400

    message = data.get("message")
    public_pem = data.get("public_key")

    if not isinstance(message, str) or not message:
        return jsonify({"error": "Message must be text."}), 400

    if not isinstance(public_pem, str):
        return jsonify({"error": "A valid public key is required."}), 400

    if len(message) > MAX_MESSAGE_LENGTH:
        return jsonify({"error": "Message is too large."}), 413

    try:
        public_key = serialization.load_pem_public_key(
            public_pem.encode("utf-8")
        )

        ciphertext = encrypt_message(
            message.encode("utf-8"),
            public_key
        )

        return jsonify({
            "success": True,
            "algorithm": "RSA-2048-OAEP-SHA256",
            "ciphertext": base64.b64encode(ciphertext).decode("utf-8")
        }), 200

    except (ValueError, TypeError):
        return jsonify({
            "error": "RSA encryption failed. Check the public key and message size."
        }), 400


# --------------------------------------------------
# RSA DECRYPTION API
# --------------------------------------------------

@encryption_bp.route("/rsa/decrypt", methods=["POST"])
def rsa_decrypt_api():
    data = get_request_data()

    if data is None:
        return jsonify({"error": "Valid JSON is required."}), 400

    ciphertext_text = data.get("ciphertext")
    private_pem = data.get("encrypted_private_key")
    password = data.get("password")

    if not isinstance(ciphertext_text, str):
        return jsonify({"error": "Ciphertext is required."}), 400

    if not isinstance(private_pem, str):
        return jsonify({"error": "Encrypted private key is required."}), 400

    if not isinstance(password, str) or not password:
        return jsonify({"error": "Private key password is required."}), 400
    if len(ciphertext_text) > 1024 or len(private_pem) > 16384:
        return jsonify({
            "error": "RSA input is too large."
        }), 413

    try:
        ciphertext = base64.b64decode(
            ciphertext_text,
            validate=True
        )

        if len(ciphertext) != 256:
            return jsonify({
                "error": "Invalid RSA ciphertext length."
            }), 400

        private_key = serialization.load_pem_private_key(
            private_pem.encode("utf-8"),
            password=password.encode("utf-8")
        )

        plaintext = decrypt_message(ciphertext, private_key)

        return jsonify({
            "success": True,
            "algorithm": "RSA-2048-OAEP-SHA256",
            "decrypted_message": plaintext.decode("utf-8")
        }), 200

    except (ValueError, TypeError, UnicodeDecodeError):
        return jsonify({
            "error": "RSA decryption failed. Check the ciphertext, key and password."
        }), 400
