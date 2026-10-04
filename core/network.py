import socket
import struct
import sys
import os
import time
import threading

from core.crypto import (
    hybrid_encrypt, hybrid_decrypt,
    compute_sha256, load_public_key, load_private_key
)
from core.logger import (
    get_logger, log_encryption, log_transfer_start, log_transfer_complete
)

BUFFER_SIZE = 4096
DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 9999


def start_server(host=DEFAULT_HOST, port=DEFAULT_PORT,
                 private_key_path="private.pem",
                 output_dir="received_files"):
    log = get_logger("Receiver")

    if not os.path.exists(output_dir):
        os.makedirs(output_dir)

    server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_sock.bind((host, port))
    server_sock.listen(1)
    log.info(f"Receiver listening on {host}:{port}")
    log.info("Waiting for incoming encrypted file...")

    conn, addr = server_sock.accept()
    log.info(f"Connection from {addr[0]}:{addr[1]}")

    try:
        start_time = time.perf_counter()

        raw_fn_len = conn.recv(4)
        fn_len = struct.unpack("!I", raw_fn_len)[0]
        filename = conn.recv(fn_len).decode("utf-8")
        log.info(f"Receiving file: '{filename}'")

        raw_bundle_len = conn.recv(8)
        bundle_len = struct.unpack("!Q", raw_bundle_len)[0]
        log.info(f"Expected bundle size: {bundle_len} bytes")

        bundle = b""
        while len(bundle) < bundle_len:
            remaining = bundle_len - len(bundle)
            chunk = conn.recv(min(BUFFER_SIZE, remaining))
            if not chunk:
                break
            bundle += chunk

        log.info(f"Received {len(bundle)} bytes")

        raw_hash_len = conn.recv(4)
        hash_len = struct.unpack("!I", raw_hash_len)[0]
        sender_hash = conn.recv(hash_len).decode("utf-8")
        log.info(f"Sender's plaintext SHA-256: {sender_hash}")

        log.info("Decrypting received bundle...")
        plaintext, metadata = hybrid_decrypt(bundle, private_key_path)

        receiver_hash = metadata["plaintext_sha256"]
        if receiver_hash == sender_hash:
            log.info(f"INTEGRITY VERIFIED -- SHA-256 hashes match!")
            integrity_ok = True
        else:
            log.warning(f"INTEGRITY FAILED -- Hashes do not match!")
            log.warning(f"  Sender:   {sender_hash}")
            log.warning(f"  Receiver: {receiver_hash}")
            integrity_ok = False

        output_path = os.path.join(output_dir, f"decrypted_{filename}")
        with open(output_path, "wb") as f:
            f.write(plaintext)

        elapsed = (time.perf_counter() - start_time) * 1000
        log_transfer_complete(log, filename, elapsed)
        log.info(f"Saved decrypted file: {output_path}")

        ack = b"OK" if integrity_ok else b"FAIL"
        conn.sendall(ack)

    except Exception as e:
        log.error(f"Error during receive: {e}")
        conn.sendall(b"FAIL")
    finally:
        conn.close()
        server_sock.close()

    return output_path if 'output_path' in dir() else None


def send_file(file_path, host=DEFAULT_HOST, port=DEFAULT_PORT,
              public_key_path="public.pem"):
    log = get_logger("Sender")

    if not os.path.exists(file_path):
        log.error(f"File not found: {file_path}")
        return False

    filename = os.path.basename(file_path)

    log.info(f"Reading file: {file_path}")
    with open(file_path, "rb") as f:
        plaintext = f.read()

    plaintext_hash = compute_sha256(plaintext)
    log.info(f"Plaintext SHA-256: {plaintext_hash}")
    log.info(f"Encrypting with hybrid AES+RSA...")

    start_enc = time.perf_counter()
    bundle, metadata = hybrid_encrypt(plaintext, public_key_path)
    enc_time = (time.perf_counter() - start_enc) * 1000
    log_encryption(log, {**metadata, "input_file": file_path, "output_file": "[network]"})
    log.info(f"Encryption completed in {enc_time:.1f} ms")

    log_transfer_start(log, host, port, filename)
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    try:
        sock.connect((host, port))
        log.info(f"Connected to {host}:{port}")

        fn_bytes = filename.encode("utf-8")
        sock.sendall(struct.pack("!I", len(fn_bytes)))
        sock.sendall(fn_bytes)

        sock.sendall(struct.pack("!Q", len(bundle)))
        sock.sendall(bundle)

        hash_bytes = plaintext_hash.encode("utf-8")
        sock.sendall(struct.pack("!I", len(hash_bytes)))
        sock.sendall(hash_bytes)

        ack = sock.recv(4)
        tx_time = (time.perf_counter() - start_enc) * 1000
        log_transfer_complete(log, filename, tx_time)

        if ack == b"OK":
            log.info("Receiver confirmed: Integrity VERIFIED")
            return True
        else:
            log.warning("Receiver reported: Integrity FAILED")
            return False

    except ConnectionRefusedError:
        log.error(f"Connection refused at {host}:{port}. Is the receiver running?")
        return False
    except Exception as e:
        log.error(f"Transfer error: {e}")
        return False
    finally:
        sock.close()


def demo_transfer(file_path="sample.txt",
                  public_key_path="public.pem",
                  private_key_path="private.pem",
                  port=0):
    log = get_logger("Demo")

    if not os.path.exists(file_path):
        log.error(f"File not found: {file_path}")
        return False

    server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_sock.bind(("127.0.0.1", port))
    actual_port = server_sock.getsockname()[1]
    server_sock.listen(1)
    log.info(f"Demo server started on port {actual_port}")

    result = {"success": False, "output_path": None}

    def server_thread():
        try:
            conn, addr = server_sock.accept()
            start_time = time.perf_counter()

            raw_fn_len = conn.recv(4)
            fn_len = struct.unpack("!I", raw_fn_len)[0]
            filename = conn.recv(fn_len).decode("utf-8")

            raw_bundle_len = conn.recv(8)
            bundle_len = struct.unpack("!Q", raw_bundle_len)[0]
            bundle = b""
            while len(bundle) < bundle_len:
                remaining = bundle_len - len(bundle)
                chunk = conn.recv(min(BUFFER_SIZE, remaining))
                if not chunk:
                    break
                bundle += chunk

            raw_hash_len = conn.recv(4)
            hash_len = struct.unpack("!I", raw_hash_len)[0]
            sender_hash = conn.recv(hash_len).decode("utf-8")

            plaintext, metadata = hybrid_decrypt(bundle, private_key_path)
            receiver_hash = metadata["plaintext_sha256"]

            integrity_ok = receiver_hash == sender_hash

            if not os.path.exists("received_files"):
                os.makedirs("received_files")
            output_path = os.path.join("received_files", f"decrypted_{filename}")
            with open(output_path, "wb") as f:
                f.write(plaintext)

            elapsed = (time.perf_counter() - start_time) * 1000
            log.info(f"Server: Received and decrypted '{filename}' in {elapsed:.1f} ms")
            log.info(f"Server: Integrity {'VERIFIED' if integrity_ok else 'FAILED'}")
            log.info(f"Server: Saved to {output_path}")

            conn.sendall(b"OK" if integrity_ok else b"FAIL")
            conn.close()

            result["success"] = integrity_ok
            result["output_path"] = output_path

        except Exception as e:
            log.error(f"Server thread error: {e}")
        finally:
            server_sock.close()

    t = threading.Thread(target=server_thread, daemon=True)
    t.start()

    time.sleep(0.1)

    success = send_file(file_path, "127.0.0.1", actual_port, public_key_path)
    t.join(timeout=10)

    if result["success"]:
        with open(file_path, "rb") as f:
            original = f.read()
        with open(result["output_path"], "rb") as f:
            received = f.read()
        if original == received:
            log.info("DEMO VERIFIED: Original and received files are IDENTICAL")
        else:
            log.warning("DEMO FAILED: Files do not match!")
            result["success"] = False

    return result["success"]
