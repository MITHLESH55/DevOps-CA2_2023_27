import os
import hashlib
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Random import get_random_bytes
from Crypto.PublicKey import RSA

RSA_KEY_SIZE = 2048
AES_KEY_SIZE = 32
RSA_BLOCK_SIZE = 256
AES_NONCE_SIZE = 16
AES_TAG_SIZE = 16
HEADER_SIZE = RSA_BLOCK_SIZE + AES_NONCE_SIZE + AES_TAG_SIZE


def compute_sha256(data):
    return hashlib.sha256(data).hexdigest()


def compute_file_sha256(file_path):
    sha256 = hashlib.sha256()
    with open(file_path, "rb") as f:
        while True:
            chunk = f.read(8192)
            if not chunk:
                break
            sha256.update(chunk)
    return sha256.hexdigest()


def generate_rsa_keys(private_path="private.pem", public_path="public.pem"):
    key = RSA.generate(RSA_KEY_SIZE)
    private_key = key.export_key()
    public_key = key.publickey().export_key()

    with open(private_path, "wb") as f:
        f.write(private_key)
    with open(public_path, "wb") as f:
        f.write(public_key)

    return private_path, public_path


def load_public_key(path="public.pem"):
    return RSA.import_key(open(path).read())


def load_private_key(path="private.pem"):
    return RSA.import_key(open(path).read())


def hybrid_encrypt(plaintext_bytes, public_key_path="public.pem"):
    aes_key = get_random_bytes(AES_KEY_SIZE)

    cipher_aes = AES.new(aes_key, AES.MODE_EAX)
    ciphertext, tag = cipher_aes.encrypt_and_digest(plaintext_bytes)

    public_key = load_public_key(public_key_path)
    cipher_rsa = PKCS1_OAEP.new(public_key)
    enc_aes_key = cipher_rsa.encrypt(aes_key)

    bundle = enc_aes_key + cipher_aes.nonce + tag + ciphertext

    metadata = {
        "aes_key_hex": aes_key.hex(),
        "nonce_hex": cipher_aes.nonce.hex(),
        "plaintext_sha256": compute_sha256(plaintext_bytes),
        "ciphertext_sha256": compute_sha256(ciphertext),
        "bundle_sha256": compute_sha256(bundle),
        "plaintext_size": len(plaintext_bytes),
        "bundle_size": len(bundle),
    }

    return bundle, metadata


def hybrid_decrypt(bundle, private_key_path="private.pem"):
    enc_aes_key = bundle[:RSA_BLOCK_SIZE]
    nonce = bundle[RSA_BLOCK_SIZE:RSA_BLOCK_SIZE + AES_NONCE_SIZE]
    tag = bundle[RSA_BLOCK_SIZE + AES_NONCE_SIZE:HEADER_SIZE]
    ciphertext = bundle[HEADER_SIZE:]

    private_key = load_private_key(private_key_path)
    cipher_rsa = PKCS1_OAEP.new(private_key)
    aes_key = cipher_rsa.decrypt(enc_aes_key)

    cipher_aes = AES.new(aes_key, AES.MODE_EAX, nonce)
    plaintext = cipher_aes.decrypt_and_verify(ciphertext, tag)

    metadata = {
        "plaintext_sha256": compute_sha256(plaintext),
        "plaintext_size": len(plaintext),
        "verified": True,
    }

    return plaintext, metadata


def encrypt_file(input_path, output_path="encrypted_file.bin",
                 public_key_path="public.pem"):
    with open(input_path, "rb") as f:
        plaintext = f.read()

    bundle, metadata = hybrid_encrypt(plaintext, public_key_path)

    with open(output_path, "wb") as f:
        f.write(bundle)

    metadata["input_file"] = input_path
    metadata["output_file"] = output_path
    return metadata


def decrypt_file(input_path, output_path="decrypted_output.txt",
                 private_key_path="private.pem"):
    with open(input_path, "rb") as f:
        bundle = f.read()

    plaintext, metadata = hybrid_decrypt(bundle, private_key_path)

    with open(output_path, "wb") as f:
        f.write(plaintext)

    metadata["input_file"] = input_path
    metadata["output_file"] = output_path
    return metadata
