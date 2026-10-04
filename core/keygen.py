import os
from core.crypto import generate_rsa_keys


def generate_keys(private_path="private.pem", public_path="public.pem"):
    print("Generating 2048-bit RSA keys...")
    generate_rsa_keys(private_path, public_path)

    priv_size = os.path.getsize(private_path)
    pub_size = os.path.getsize(public_path)

    print(f"RSA keys generated successfully!")
    print(f"  Private key: {private_path} ({priv_size} bytes)")
    print(f"  Public key:  {public_path} ({pub_size} bytes)")
