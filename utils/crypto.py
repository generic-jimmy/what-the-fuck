"""
utils/crypto.py
AES-256 (Fernet) encryption for storing GitHub tokens at rest.
"""

import base64
import os

from cryptography.fernet import Fernet


def _get_fernet() -> Fernet:
    key = os.getenv("ENCRYPTION_KEY")
    if not key:
        raise RuntimeError("ENCRYPTION_KEY environment variable is not set.")
    # Accept raw 32-byte key or URL-safe base64 Fernet key
    try:
        return Fernet(key.encode())
    except Exception:
        # If the key isn't already Fernet format, derive one
        raw = key.encode()[:32].ljust(32, b"0")
        fernet_key = base64.urlsafe_b64encode(raw)
        return Fernet(fernet_key)


def encrypt_token(plain_token: str) -> str:
    """Encrypt a plaintext GitHub PAT. Returns a base64 string."""
    f = _get_fernet()
    return f.encrypt(plain_token.encode()).decode()


def decrypt_token(encrypted: str) -> str:
    """Decrypt a stored token back to plaintext."""
    f = _get_fernet()
    return f.decrypt(encrypted.encode()).decode()


def generate_key() -> str:
    """Generate a new Fernet key — run once and store in .env."""
    return Fernet.generate_key().decode()


if __name__ == "__main__":
    print("Generated ENCRYPTION_KEY:", generate_key())
