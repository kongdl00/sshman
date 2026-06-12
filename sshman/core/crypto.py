import os
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag


class CryptoError(Exception):
    """Raised when crypto operations fail (wrong password, corrupted data, etc.)."""
    pass


def derive_key(password: str, salt: str) -> bytes:
    """Derive a 32-byte AES-256 key from password using Argon2id.

    Args:
        password: User's master password (must be non-empty).
        salt: Salt string (must be non-empty).

    Returns:
        32-byte derived key.

    Raises:
        CryptoError: If password or salt is empty.
    """
    if not password:
        raise CryptoError("password must not be empty")
    if not salt:
        raise CryptoError("salt must not be empty")

    salt_bytes = salt.encode("utf-8")
    # Argon2id requires salt to be at least 8 bytes
    if len(salt_bytes) < 8:
        salt_bytes = salt_bytes.ljust(8, b"\x00")
    kdf = Argon2id(
        salt=salt_bytes,
        length=32,
        memory_cost=65536,   # 64 MB
        iterations=3,
        lanes=4,
    )
    return kdf.derive(password.encode("utf-8"))


def encrypt_data(plaintext: bytes, key: bytes) -> bytes:
    """Encrypt data using AES-256-GCM.

    Each call generates a fresh 96-bit nonce. The ciphertext format is:
    nonce (12 bytes) + ciphertext.

    Args:
        plaintext: Data to encrypt.
        key: 32-byte AES key.

    Returns:
        Encrypted bytes (nonce + ciphertext).
    """
    nonce = os.urandom(12)
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, plaintext, None)
    return nonce + ciphertext


def decrypt_data(ciphertext: bytes, key: bytes) -> bytes:
    """Decrypt data using AES-256-GCM.

    Args:
        ciphertext: Encrypted bytes (nonce + ciphertext).
        key: 32-byte AES key.

    Returns:
        Decrypted plaintext bytes.

    Raises:
        CryptoError: If decryption fails (wrong key, tampered data).
    """
    if len(ciphertext) < 12:
        raise CryptoError("ciphertext too short — must be at least 12 bytes")
    nonce = ciphertext[:12]
    encrypted = ciphertext[12:]
    aesgcm = AESGCM(key)
    try:
        return aesgcm.decrypt(nonce, encrypted, None)
    except InvalidTag:
        raise CryptoError("decryption failed — wrong password or corrupted data")
