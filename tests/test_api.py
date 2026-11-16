
import json

from app import create_app

from app import app

def test_health_endpoint():
    client = app.test_client()

def setup_client():
    app = create_app()
    app.config["TESTING"] = True
    return app.test_client()


def test_health_endpoint():
    client = setup_client()

    response = client.get("/api/health")

    assert response.status_code == 200
    assert response.json["status"] == "online"


def test_api_encryption():
    client = setup_client()

    response = client.post("/api/encrypt", json={
        "message": "Hello SecureText!",
        "password": "MyStrongPassword123!"
    })

    assert response.status_code == 200
    assert response.json["success"] is True
    assert response.json["algorithm"] == "AES-256-GCM"


def test_api_decryption():
    client = setup_client()

    encrypted = client.post("/api/encrypt", json={
        "message": "Confidential information",
        "password": "MyStrongPassword123!"
    })

    payload = encrypted.json

    response = client.post("/api/decrypt", json={
        "encrypted_data": payload["encrypted_data"],
        "key_metadata": payload["key_metadata"],
        "password": "MyStrongPassword123!"
    })

    assert response.status_code == 200
    assert response.json["decrypted_message"] == "Confidential information"


def test_api_wrong_password():
    client = setup_client()

    encrypted = client.post("/api/encrypt", json={
        "message": "Secret message",
        "password": "CorrectPassword123!"
    })

    payload = encrypted.json

    response = client.post("/api/decrypt", json={
        "encrypted_data": payload["encrypted_data"],
        "key_metadata": payload["key_metadata"],
        "password": "WrongPassword123!"
    })

    assert response.status_code == 400


def test_api_rejects_empty_message():
    client = setup_client()

    response = client.post("/api/encrypt", json={
        "message": "",
        "password": "MyStrongPassword123!"
    })

    assert response.status_code == 400


def test_caesar_api_encryption():
    client = setup_client()

    response = client.post("/api/caesar/encrypt", json={
        "message": "HELLO",
        "shift": 3
    })

    assert response.status_code == 200
    assert response.json["encrypted_message"] == "KHOOR"


def test_caesar_api_decryption():
    client = setup_client()

    response = client.post("/api/caesar/decrypt", json={
        "message": "KHOOR",
        "shift": 3
    })

    assert response.status_code == 200
    assert response.json["decrypted_message"] == "HELLO"


def test_vigenere_api_encryption():
    client = setup_client()

    response = client.post("/api/vigenere/encrypt", json={
        "message": "ATTACKATDAWN",
        "key": "LEMON"
    })

    assert response.status_code == 200
    assert response.json["encrypted_message"] == "LXFOPVEFRNHR"


def test_vigenere_api_decryption():
    client = setup_client()

    response = client.post("/api/vigenere/decrypt", json={
        "message": "LXFOPVEFRNHR",
        "key": "LEMON"
    })

    assert response.status_code == 200
    assert response.json["decrypted_message"] == "ATTACKATDAWN"


def test_vigenere_api_rejects_invalid_key():
    client = setup_client()

    response = client.post("/api/vigenere/encrypt", json={
        "message": "HELLO",
        "key": "12345"
    })

    assert response.status_code == 400


def test_caesar_api_rejects_invalid_shift():
    client = setup_client()

    response = client.post("/api/caesar/encrypt", json={
        "message": "HELLO",
        "shift": "three"
    })

    assert response.status_code == 400


def test_rsa_api_key_generation():
    client = setup_client()

    response = client.post("/api/rsa/keys", json={
        "password": "MyStrongPrivateKey123!"
    })

    assert response.status_code == 200
    assert response.json["success"] is True
    assert "public_key" in response.json
    assert "encrypted_private_key" in response.json


def test_rsa_api_encryption():
    client = setup_client()

    keys = client.post("/api/rsa/keys", json={
        "password": "MyStrongPrivateKey123!"
    })

    public_key = keys.json["public_key"]

    response = client.post("/api/rsa/encrypt", json={
        "message": "Hello SecureText RSA!",
        "public_key": public_key
    })

    assert response.status_code == 200
    assert response.json["success"] is True
    assert "ciphertext" in response.json


def test_rsa_api_decryption():
    client = setup_client()

    password = "MyStrongPrivateKey123!"

    keys = client.post("/api/rsa/keys", json={
        "password": password
    })

    encrypted = client.post("/api/rsa/encrypt", json={
        "message": "Confidential RSA message",
        "public_key": keys.json["public_key"]
    })

    response = client.post("/api/rsa/decrypt", json={
        "ciphertext": encrypted.json["ciphertext"],
        "encrypted_private_key": keys.json["encrypted_private_key"],
        "password": password
    })

    assert response.status_code == 200
    assert response.json["decrypted_message"] == "Confidential RSA message"


def test_rsa_api_wrong_password():
    client = setup_client()

    keys = client.post("/api/rsa/keys", json={
        "password": "CorrectPrivateKey123!"
    })

    encrypted = client.post("/api/rsa/encrypt", json={
        "message": "Secret message",
        "public_key": keys.json["public_key"]
    })

    response = client.post("/api/rsa/decrypt", json={
        "ciphertext": encrypted.json["ciphertext"],
        "encrypted_private_key": keys.json["encrypted_private_key"],
        "password": "WrongPrivateKey123!"
    })

    assert response.status_code == 400


def test_rsa_api_rejects_large_message():
    client = setup_client()

    keys = client.post("/api/rsa/keys", json={
        "password": "MyStrongPrivateKey123!"
    })

    response = client.post("/api/rsa/encrypt", json={
        "message": "A" * 191,
        "public_key": keys.json["public_key"]
    })

    assert response.status_code == 400



def test_file_api_encryption_and_decryption():
    import io
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.primitives.serialization import BestAvailableEncryption

    client = setup_client()

    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    public_key = private_key.public_key()

    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode("utf-8")

    password = b"SecureTestPassword123!"

    encrypted_private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=BestAvailableEncryption(password)
    ).decode("utf-8")

    original_data = b"This is my confidential SecureText test file."

    encrypt_response = client.post(
        "/api/files/encrypt",
        data={
            "file": (io.BytesIO(original_data), "sample.txt"),
            "public_key": public_pem
        },
        content_type="multipart/form-data"
    )

    assert encrypt_response.status_code == 200

    encrypted_data = encrypt_response.data

    decrypt_response = client.post(
        "/api/files/decrypt",
        data={
            "file": (io.BytesIO(encrypted_data), "sample.txt.securetext"),
            "encrypted_private_key": encrypted_private_pem,
            "password": password.decode("utf-8")
        },
        content_type="multipart/form-data"
    )

    assert decrypt_response.status_code == 200
    assert decrypt_response.data == original_data


def test_file_api_rejects_missing_file():
    client = setup_client()

    response = client.post(
        "/api/files/encrypt",
        data={"public_key": "test"},
        content_type="multipart/form-data"
    )

    assert response.status_code == 400


def test_file_api_rejects_missing_public_key():
    import io

    client = setup_client()

    response = client.post(
        "/api/files/encrypt",
        data={
            "file": (io.BytesIO(b"test content"), "test.txt")
        },
        content_type="multipart/form-data"
    )

    assert response.status_code == 400


def test_file_api_rejects_missing_private_key():
    import io

    client = setup_client()

    response = client.post(
        "/api/files/decrypt",
        data={
            "file": (io.BytesIO(b"invalid package"), "test.securetext"),
            "password": "SomePassword123!"
        },
        content_type="multipart/form-data"
    )

    assert response.status_code == 400
