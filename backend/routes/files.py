
import io

from flask import Blueprint, request, jsonify, send_file
from werkzeug.utils import secure_filename
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.exceptions import InvalidTag

from backend.crypto.hybrid import encrypt_file_data, decrypt_file_data


files_bp = Blueprint("files", __name__)

MAX_FILE_SIZE = 5 * 1024 * 1024


@files_bp.route("/files/encrypt", methods=["POST"])
def encrypt_uploaded_file():
    uploaded_file = request.files.get("file")
    public_key_pem = request.form.get("public_key")

    if not uploaded_file or not uploaded_file.filename:
        return jsonify({
            "success": False,
            "error": "Please upload a file."
        }), 400

    if not public_key_pem:
        return jsonify({
            "success": False,
            "error": "RSA public key is required."
        }), 400

    file_data = uploaded_file.read(MAX_FILE_SIZE + 1)

    if not file_data:
        return jsonify({
            "success": False,
            "error": "The uploaded file is empty."
        }), 400

    if len(file_data) > MAX_FILE_SIZE:
        return jsonify({
            "success": False,
            "error": "File exceeds the 5 MB limit."
        }), 413

    try:
        public_key = serialization.load_pem_public_key(
            public_key_pem.encode("utf-8")
        )

        if not isinstance(public_key, rsa.RSAPublicKey):
            raise ValueError("An RSA public key is required.")

        encrypted_package = encrypt_file_data(
            file_data,
            public_key
        )

        original_name = secure_filename(uploaded_file.filename)
        download_name = (original_name or "file") + ".securetext"

        return send_file(
            io.BytesIO(encrypted_package.encode("utf-8")),
            mimetype="application/octet-stream",
            as_attachment=True,
            download_name=download_name
        )

    except (ValueError, TypeError) as exc:
        return jsonify({
            "success": False,
            "error": str(exc)
        }), 400


@files_bp.route("/files/decrypt", methods=["POST"])
def decrypt_uploaded_file():
    uploaded_file = request.files.get("file")
    encrypted_private_key_pem = request.form.get(
        "encrypted_private_key"
    )
    password = request.form.get("password")

    if not uploaded_file:
        return jsonify({
            "success": False,
            "error": "Please upload an encrypted file."
        }), 400

    if not encrypted_private_key_pem or not password:
        return jsonify({
            "success": False,
            "error": "Encrypted private key and password are required."
        }), 400

    package_data = uploaded_file.read(MAX_FILE_SIZE + 1)

    if not package_data:
        return jsonify({
            "success": False,
            "error": "The encrypted file is empty."
        }), 400

    if len(package_data) > MAX_FILE_SIZE:
        return jsonify({
            "success": False,
            "error": "Encrypted file exceeds the 5 MB limit."
        }), 413

    try:
        private_key = serialization.load_pem_private_key(
            encrypted_private_key_pem.encode("utf-8"),
            password=password.encode("utf-8")
        )

        if not isinstance(private_key, rsa.RSAPrivateKey):
            raise ValueError("An RSA private key is required.")

        decrypted_data = decrypt_file_data(
            package_data.decode("utf-8"),
            private_key
        )

        return send_file(
            io.BytesIO(decrypted_data),
            mimetype="application/octet-stream",
            as_attachment=True,
            download_name="decrypted_file"
        )

    except InvalidTag:
        return jsonify({
            "success": False,
            "error": "File authentication failed. The encrypted file may have been modified."
        }), 400

    except (ValueError, TypeError):
        return jsonify({
            "success": False,
            "error": "File encryption failed. Check the RSA public key and uploaded file."
        }), 400
