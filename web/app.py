import os
import sys
import time
import uuid
import socket
import struct
import threading
from datetime import datetime

from flask import Flask, render_template, request, jsonify, send_file, redirect, Response
from werkzeug.utils import secure_filename
from prometheus_client import Counter, Histogram, Gauge, generate_latest, CONTENT_TYPE_LATEST

from core.crypto import (
    generate_rsa_keys,
    hybrid_encrypt,
    hybrid_decrypt,
    encrypt_file,
    decrypt_file,
    compute_sha256,
    compute_file_sha256,
    HEADER_SIZE,
)

from Crypto.PublicKey import RSA


# ================================================================
# Application Configuration
# ================================================================

WEB_DIR = os.path.dirname(os.path.abspath(__file__))
TEMPLATE_DIR = os.path.join(WEB_DIR, "templates")

app = Flask(__name__, template_folder=TEMPLATE_DIR)
 
# ================================================================
# PROMETHEUS MONITORING METRICS
# ================================================================
METRICS_START_TIME = time.time()

HTTP_REQUESTS = Counter(
    "sft_http_requests_total",
    "Total HTTP requests received by the Secure File Transfer application",
    ["method", "endpoint", "status"],
)

HTTP_ERRORS = Counter(
    "sft_http_errors_total",
    "Total HTTP requests returning client/server errors",
    ["method", "endpoint", "status"],
)

HTTP_LATENCY = Histogram(
    "sft_http_request_duration_seconds",
    "HTTP request latency in seconds",
    ["method", "endpoint"],
)

APP_UPTIME = Gauge(
    "sft_uptime_seconds",
    "Application uptime in seconds",
)

APP_UPTIME.set_function(
    lambda: time.time() - METRICS_START_TIME
)


@app.before_request
def metrics_before_request():
    if request.path != "/metrics":
        request._sft_request_start = time.perf_counter()


@app.after_request
def metrics_after_request(response):
    if request.path == "/metrics":
        return response

    start = getattr(request, "_sft_request_start", None)

    endpoint = (
        request.url_rule.rule
        if request.url_rule
        else "unmatched"
    )

    method = request.method
    status = str(response.status_code)

    HTTP_REQUESTS.labels(
        method=method,
        endpoint=endpoint,
        status=status,
    ).inc()

    if start is not None:
        HTTP_LATENCY.labels(
            method=method,
            endpoint=endpoint,
        ).observe(
            time.perf_counter() - start
        )

    if response.status_code >= 400:
        HTTP_ERRORS.labels(
            method=method,
            endpoint=endpoint,
            status=status,
        ).inc()

    return response


@app.route("/metrics")
def metrics():
    return Response(
        generate_latest(),
        mimetype=CONTENT_TYPE_LATEST,
    )



# Application version.
# This value can be changed using the APP_VERSION environment
# variable during Docker/Kubernetes deployments.
APP_VERSION = os.getenv("APP_VERSION", "1.0.0")

# Maximum upload size: 50 MB
app.config["MAX_CONTENT_LENGTH"] = 50 * 1024 * 1024

PROJECT_ROOT = os.path.dirname(WEB_DIR)

# Runtime workspace for generated keys and transferred files.
WORK_DIR = os.path.join(PROJECT_ROOT, "web_workspace")
os.makedirs(WORK_DIR, exist_ok=True)


# ================================================================
# In-Memory Application State
# ================================================================

transfers = {}
audit_log = []


# ================================================================
# Logging / Audit Utility
# ================================================================

def log_event(event_type, message, transfer_id=None):
    entry = {
        "timestamp": datetime.now().strftime("%H:%M:%S"),
        "type": event_type,
        "message": message,
        "transfer_id": transfer_id or "",
    }

    audit_log.append(entry)


# ================================================================
# Web Pages
# ================================================================

@app.route("/")
def index():
    return redirect("/receiver")


@app.route("/sender")
def sender_page():
    return render_template("sender.html")


@app.route("/receiver")
def receiver_page():
    return render_template("receiver.html")


# ================================================================
# Deployment / Version Endpoint
# ================================================================

@app.route("/api/version")
def api_version():
    """
    Return the currently running application version.

    Used for:
    - deployment verification
    - Docker verification
    - Kubernetes rolling update demonstration
    - Kubernetes rollback verification
    """
    return jsonify({
        "application": "Secure File Transfer System",
        "version": APP_VERSION,
        "status": "running",
    })


# ================================================================
# RECEIVER: Generate RSA-2048 key pair
# Private key remains on the server
# ================================================================

@app.route("/api/receiver/init-transfer", methods=["POST"])
def receiver_init_transfer():
    """
    Receiver generates RSA-2048 key pair.

    Private key stays on the server and is never shared.
    Public key is returned for the receiver to share with sender.
    """

    try:
        # Generate an 8-character transfer ID
        transfer_id = str(uuid.uuid4())[:8].upper()

        t_dir = os.path.join(WORK_DIR, transfer_id)
        os.makedirs(t_dir, exist_ok=True)

        priv_path = os.path.join(t_dir, "private.pem")
        pub_path = os.path.join(t_dir, "public.pem")

        start = time.perf_counter()

        generate_rsa_keys(priv_path, pub_path)

        elapsed = (time.perf_counter() - start) * 1000

        with open(pub_path, "r") as f:
            public_key_text = f.read()

        transfers[transfer_id] = {
            "status": "keys_generated",
            "dir": t_dir,
            "priv_path": priv_path,
            "pub_path": pub_path,
            "created": datetime.now().isoformat(),
            "original_name": None,
            "encrypted_path": None,
            "received_path": None,
        }

        log_event(
            "KEY_GEN",
            f"RSA-2048 keys generated by RECEIVER for transfer {transfer_id}",
            transfer_id,
        )

        return jsonify({
            "success": True,
            "transfer_id": transfer_id,
            "public_key": public_key_text,
            "public_key_preview": public_key_text[:120] + "...",
            "time_ms": round(elapsed, 2),
        })

    except Exception as e:
        return jsonify({
            "success": False,
            "error": str(e),
        }), 500


# ================================================================
# SENDER: Encrypt and transfer file
# ================================================================

@app.route("/api/sender/encrypt", methods=["POST"])
def sender_encrypt():
    """
    Sender uploads a file along with the Transfer ID and public key
    received from the receiver.

    The server validates the supplied public key against the
    receiver's stored public key, then encrypts the file.

    Hybrid encryption:
        AES-256-EAX  -> encrypt file
        RSA-2048-OAEP -> protect AES session key
    """

    try:
        transfer_id = request.form.get(
            "transfer_id",
            "",
        ).strip().upper()

        sender_public_key = request.form.get(
            "public_key",
            "",
        ).strip()

        # --------------------------------------------------------
        # Validate transfer ID
        # --------------------------------------------------------

        if not transfer_id or transfer_id not in transfers:
            return jsonify({
                "success": False,
                "error": (
                    "Invalid Transfer ID. "
                    "Ask the receiver for the correct ID."
                ),
            }), 400

        # --------------------------------------------------------
        # Validate public key
        # --------------------------------------------------------

        if not sender_public_key:
            return jsonify({
                "success": False,
                "error": (
                    "Public key is required. "
                    "Paste the public key you received from the receiver."
                ),
            }), 400

        try:
            submitted_key = RSA.import_key(sender_public_key)

        except Exception:
            return jsonify({
                "success": False,
                "error": (
                    "Invalid public key format. "
                    "Please paste the complete PEM public key "
                    "from the receiver."
                ),
            }), 400

        # --------------------------------------------------------
        # Verify supplied public key
        # --------------------------------------------------------

        t = transfers[transfer_id]

        with open(t["pub_path"], "r") as f:
            stored_public_key = f.read()

        stored_key = RSA.import_key(stored_public_key)

        if submitted_key.export_key() != stored_key.export_key():
            return jsonify({
                "success": False,
                "error": (
                    "Public key DOES NOT MATCH the receiver's key "
                    "for this Transfer ID. "
                    "Verify you have the correct key from the receiver."
                ),
            }), 400

        # --------------------------------------------------------
        # Validate uploaded file
        # --------------------------------------------------------

        if "file" not in request.files:
            return jsonify({
                "success": False,
                "error": "No file uploaded",
            }), 400

        file = request.files["file"]

        if file.filename == "":
            return jsonify({
                "success": False,
                "error": "No file selected",
            }), 400

        t_dir = t["dir"]

        # --------------------------------------------------------
        # Store sender-provided public key
        # --------------------------------------------------------

        sender_pub_path = os.path.join(
            t_dir,
            "sender_provided_public.pem",
        )

        with open(sender_pub_path, "w") as f:
            f.write(sender_public_key)

        pub_path = sender_pub_path

        log_event(
            "KEY_VERIFY",
            (
                "Sender's public key VERIFIED against "
                f"receiver's key for transfer {transfer_id}"
            ),
            transfer_id,
        )

        # --------------------------------------------------------
        # Save original file
        # --------------------------------------------------------

        original_name = secure_filename(file.filename)

        upload_path = os.path.join(
            t_dir,
            "original_" + original_name,
        )

        file.save(upload_path)

        original_size = os.path.getsize(upload_path)

        original_hash = compute_file_sha256(upload_path)

        # --------------------------------------------------------
        # AES-256-EAX encryption +
        # RSA-2048-OAEP key wrapping
        # --------------------------------------------------------

        enc_path = os.path.join(
            t_dir,
            original_name + ".enc",
        )

        start = time.perf_counter()

        metadata = encrypt_file(
            upload_path,
            enc_path,
            pub_path,
        )

        enc_time = (
            time.perf_counter() - start
        ) * 1000

        enc_size = os.path.getsize(enc_path)

        # Preview encrypted bytes
        with open(enc_path, "rb") as f:
            hex_preview = f.read(80).hex()

        # Read encrypted bundle
        with open(enc_path, "rb") as f:
            bundle = f.read()

        # --------------------------------------------------------
        # TCP socket transfer
        # Localhost simulation
        # --------------------------------------------------------

        server_sock = socket.socket(
            socket.AF_INET,
            socket.SOCK_STREAM,
        )

        server_sock.setsockopt(
            socket.SOL_SOCKET,
            socket.SO_REUSEADDR,
            1,
        )

        server_sock.bind(
            ("127.0.0.1", 0),
        )

        port = server_sock.getsockname()[1]

        server_sock.listen(1)

        received = {
            "data": b"",
            "ok": False,
        }

        def server_fn():
            try:
                conn, addr = server_sock.accept()

                raw_len = conn.recv(8)

                blen = struct.unpack(
                    "!Q",
                    raw_len,
                )[0]

                buf = b""

                while len(buf) < blen:
                    chunk = conn.recv(
                        min(
                            4096,
                            blen - len(buf),
                        )
                    )

                    if not chunk:
                        break

                    buf += chunk

                received["data"] = buf
                received["ok"] = True

                conn.sendall(b"ACK")

                conn.close()

            except Exception:
                pass

            finally:
                server_sock.close()

        srv_t = threading.Thread(
            target=server_fn,
            daemon=True,
        )

        srv_t.start()

        time.sleep(0.05)

        # --------------------------------------------------------
        # Send encrypted bundle
        # --------------------------------------------------------

        tx_start = time.perf_counter()

        csock = socket.socket(
            socket.AF_INET,
            socket.SOCK_STREAM,
        )

        csock.connect(
            ("127.0.0.1", port),
        )

        csock.sendall(
            struct.pack(
                "!Q",
                len(bundle),
            )
        )

        csock.sendall(bundle)

        csock.recv(4)

        csock.close()

        tx_time = (
            time.perf_counter() - tx_start
        ) * 1000

        srv_t.join(timeout=10)

        # --------------------------------------------------------
        # Save received encrypted bundle
        # --------------------------------------------------------

        recv_path = os.path.join(
            t_dir,
            "received_" + original_name + ".enc",
        )

        with open(recv_path, "wb") as f:
            f.write(received["data"])

        # --------------------------------------------------------
        # SHA-256 integrity verification
        # --------------------------------------------------------

        sent_hash = compute_sha256(bundle)

        recv_hash = compute_sha256(
            received["data"],
        )

        # Update transfer state
        t["status"] = "transferred"
        t["original_name"] = original_name
        t["original_size"] = original_size
        t["original_hash"] = original_hash
        t["encrypted_path"] = enc_path
        t["received_path"] = recv_path
        t["enc_size"] = enc_size

        log_event(
            "ENCRYPT",
            (
                f"File '{original_name}' encrypted with "
                f"RECEIVER's public key ({enc_time:.0f}ms)"
            ),
            transfer_id,
        )

        log_event(
            "TRANSFER",
            (
                f"TCP transfer on port {port} "
                f"({tx_time:.0f}ms, {len(bundle)} bytes)"
            ),
            transfer_id,
        )

        return jsonify({
            "success": True,
            "original_name": original_name,
            "original_size": original_size,
            "encrypted_size": enc_size,
            "sha256_original": original_hash,
            "sha256_bundle": metadata["bundle_sha256"],
            "encrypt_time_ms": round(enc_time, 2),
            "transfer_port": port,
            "bytes_transferred": len(bundle),
            "transfer_integrity": sent_hash == recv_hash,
            "transfer_time_ms": round(tx_time, 2),
            "hex_preview": hex_preview,
        })

    except Exception as e:
        return jsonify({
            "success": False,
            "error": str(e),
        }), 500


# ================================================================
# RECEIVER: Check transfer status
# ================================================================

@app.route("/api/receiver/check", methods=["POST"])
def receiver_check():
    try:
        data = request.get_json()

        transfer_id = data.get(
            "transfer_id",
            "",
        ).strip().upper()

        if transfer_id not in transfers:
            return jsonify({
                "success": False,
                "error": "Transfer ID not found.",
            }), 404

        t = transfers[transfer_id]

        if t["status"] != "transferred":
            return jsonify({
                "success": False,
                "error": (
                    "File has not been sent yet. "
                    "Wait for sender to upload."
                ),
            }), 400

        return jsonify({
            "success": True,
            "transfer_id": transfer_id,
            "original_name": t["original_name"],
            "encrypted_size": t["enc_size"],
            "original_size": t["original_size"],
            "timestamp": t["created"],
        })

    except Exception as e:
        return jsonify({
            "success": False,
            "error": str(e),
        }), 500


# ================================================================
# RECEIVER: Decrypt file using private key
# ================================================================

@app.route("/api/receiver/decrypt", methods=["POST"])
def receiver_decrypt():
    """
    Receiver decrypts the file using the RSA private key
    stored on the server.
    """

    try:
        data = request.get_json()

        transfer_id = data.get(
            "transfer_id",
            "",
        ).strip().upper()

        if transfer_id not in transfers:
            return jsonify({
                "success": False,
                "error": "Transfer ID not found.",
            }), 404

        t = transfers[transfer_id]

        if t["status"] not in (
            "transferred",
            "decrypted",
        ):
            return jsonify({
                "success": False,
                "error": "No file available to decrypt.",
            }), 400

        # Private key remains on server
        priv_path = t["priv_path"]

        dec_path = os.path.join(
            t["dir"],
            "decrypted_" + t["original_name"],
        )

        start = time.perf_counter()

        try:
            metadata = decrypt_file(
                t["received_path"],
                dec_path,
                priv_path,
            )

        except ValueError:
            return jsonify({
                "success": False,
                "error": (
                    "DECRYPTION FAILED — "
                    "Data may have been tampered with!"
                ),
            }), 400

        elapsed = (
            time.perf_counter() - start
        ) * 1000

        dec_hash = metadata["plaintext_sha256"]

        integrity = (
            dec_hash == t["original_hash"]
        )

        t["status"] = "decrypted"
        t["decrypted_path"] = dec_path

        log_event(
            "DECRYPT",
            (
                "File decrypted using receiver's PRIVATE KEY "
                f"({elapsed:.0f}ms), integrity: "
                f"{'VERIFIED' if integrity else 'FAILED'}"
            ),
            transfer_id,
        )

        return jsonify({
            "success": True,
            "original_name": t["original_name"],
            "decrypted_size": os.path.getsize(dec_path),
            "sha256_original": t["original_hash"],
            "sha256_decrypted": dec_hash,
            "integrity_verified": integrity,
            "time_ms": round(elapsed, 2),
            "download_url": (
                f"/api/receiver/download/{transfer_id}"
            ),
        })

    except Exception as e:
        return jsonify({
            "success": False,
            "error": str(e),
        }), 500


# ================================================================
# RECEIVER: Download decrypted file
# ================================================================

@app.route("/api/receiver/download/<transfer_id>")
def receiver_download(transfer_id):
    transfer_id = transfer_id.upper()

    if transfer_id not in transfers:
        return jsonify({
            "error": "Not found",
        }), 404

    t = transfers[transfer_id]

    if "decrypted_path" not in t:
        return jsonify({
            "error": "Not decrypted yet",
        }), 400

    return send_file(
        t["decrypted_path"],
        as_attachment=True,
        download_name=t["original_name"],
    )


# ================================================================
# Audit Log API
# ================================================================

@app.route("/api/audit-log")
def api_audit():
    return jsonify({
        "log": audit_log[-50:],
    })


# ================================================================
# Application Runner
# ================================================================

def run_web():
    print()
    print("=" * 62)
    print("  SECURE FILE TRANSFER SYSTEM - Two-User Web Demo")
    print("  (Secure Key Distribution: Receiver generates keys)")
    print("=" * 62)
    print()

    print(
        "  Step 1 -> Receiver:  "
        "http://localhost:5000/receiver"
    )

    print(
        "            (Generate keys, share Transfer ID + Public Key)"
    )

    print()

    print(
        "  Step 2 -> Sender:    "
        "http://localhost:5000/sender"
    )

    print(
        "            (Enter Transfer ID, upload & encrypt file)"
    )

    print()

    print(
        "  Step 3 -> Receiver:  "
        "(Check status, decrypt & download)"
    )

    print()

    print("=" * 62)
    print()

    app.run(
        debug=False,
        host="0.0.0.0",
        port=5000,
    )


# ================================================================
# Direct Execution
# ================================================================

if __name__ == "__main__":
    run_web()
