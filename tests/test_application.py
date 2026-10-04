import io

from web.app import app, transfers, audit_log


def setup_function():
    """Reset in-memory application state before each test."""
    transfers.clear()
    audit_log.clear()


def test_home_redirects_to_receiver():
    """Verify the home route redirects to the receiver page."""
    client = app.test_client()

    response = client.get("/")

    assert response.status_code == 302
    assert response.location.endswith("/receiver")


def test_sender_page_loads():
    """Verify the sender interface is available."""
    client = app.test_client()

    response = client.get("/sender")

    assert response.status_code == 200


def test_receiver_page_loads():
    """Verify the receiver interface is available."""
    client = app.test_client()

    response = client.get("/receiver")

    assert response.status_code == 200


def test_version_endpoint():
    """Verify the deployment version endpoint."""
    client = app.test_client()

    response = client.get("/api/version")

    assert response.status_code == 200

    data = response.get_json()

    assert data["application"] == "Secure File Transfer System"
    assert data["version"] == "1.0.0"
    assert data["status"] == "running"


def test_receiver_can_generate_rsa_keys():
    """Verify receiver initialization creates RSA keys."""
    client = app.test_client()

    response = client.post("/api/receiver/init-transfer")

    assert response.status_code == 200

    data = response.get_json()

    assert data["success"] is True
    assert data["transfer_id"]
    assert data["public_key"]

    assert "BEGIN PUBLIC KEY" in data["public_key"]


def test_end_to_end_secure_file_transfer():
    """
    Integration test:
    1. Receiver generates RSA keys.
    2. Sender uploads a file.
    3. File is encrypted and transferred.
    4. Receiver decrypts the file.
    5. Integrity is verified.
    6. Decrypted file is downloaded.
    """

    client = app.test_client()

    # ------------------------------------------------------------
    # Receiver initializes transfer
    # ------------------------------------------------------------

    init_response = client.post(
        "/api/receiver/init-transfer"
    )

    assert init_response.status_code == 200

    init_data = init_response.get_json()

    transfer_id = init_data["transfer_id"]
    public_key = init_data["public_key"]

    # ------------------------------------------------------------
    # Sender uploads file
    # ------------------------------------------------------------

    original_content = (
        b"CA-II DevOps secure transfer test file."
    )

    encrypt_response = client.post(
        "/api/sender/encrypt",
        data={
            "transfer_id": transfer_id,
            "public_key": public_key,
            "file": (
                io.BytesIO(original_content),
                "ca2-test.txt",
            ),
        },
        content_type="multipart/form-data",
    )

    assert encrypt_response.status_code == 200

    encrypt_data = encrypt_response.get_json()

    assert encrypt_data["success"] is True
    assert encrypt_data["transfer_integrity"] is True
    assert encrypt_data["original_name"] == "ca2-test.txt"

    # ------------------------------------------------------------
    # Receiver decrypts file
    # ------------------------------------------------------------

    decrypt_response = client.post(
        "/api/receiver/decrypt",
        json={
            "transfer_id": transfer_id
        },
    )

    assert decrypt_response.status_code == 200

    decrypt_data = decrypt_response.get_json()

    assert decrypt_data["success"] is True
    assert decrypt_data["integrity_verified"] is True
    assert decrypt_data["original_name"] == "ca2-test.txt"

    # ------------------------------------------------------------
    # Download and verify content
    # ------------------------------------------------------------

    download_response = client.get(
        f"/api/receiver/download/{transfer_id}"
    )

    assert download_response.status_code == 200
    assert download_response.data == original_content


def test_invalid_transfer_id_is_rejected():
    """Verify an unknown transfer ID is rejected."""
    client = app.test_client()

    response = client.post(
        "/api/receiver/check",
        json={
            "transfer_id": "INVALID1"
        },
    )

    assert response.status_code == 404

    data = response.get_json()

    assert data["success"] is False