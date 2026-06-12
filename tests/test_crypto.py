import pytest
from sshman.core.crypto import (
    derive_key,
    encrypt_data,
    decrypt_data,
    CryptoError,
)


class TestDeriveKey:
    def test_derive_key_returns_bytes(self):
        """derive_key returns bytes of correct length (32 for AES-256)."""
        key = derive_key("mypassword", "randomsalt")
        assert isinstance(key, bytes)
        assert len(key) == 32

    def test_same_password_salt_produces_same_key(self):
        """Same inputs produce identical derived key."""
        k1 = derive_key("pass1", "salt1")
        k2 = derive_key("pass1", "salt1")
        assert k1 == k2

    def test_different_password_produces_different_key(self):
        """Different passwords produce different keys."""
        k1 = derive_key("pass1", "salt1")
        k2 = derive_key("pass2", "salt1")
        assert k1 != k2

    def test_different_salt_produces_different_key(self):
        """Different salts produce different keys."""
        k1 = derive_key("pass1", "salt1")
        k2 = derive_key("pass1", "salt2")
        assert k1 != k2

    def test_empty_password_raises(self):
        """Empty password raises CryptoError."""
        with pytest.raises(CryptoError, match="password"):
            derive_key("", "salt")

    def test_empty_salt_raises(self):
        """Empty salt raises CryptoError."""
        with pytest.raises(CryptoError, match="salt"):
            derive_key("pass", "")


class TestEncryptDecrypt:
    def test_encrypt_returns_bytes(self):
        """encrypt_data returns ciphertext as bytes."""
        key = derive_key("mypass", "mysalt")
        ciphertext = encrypt_data(b"hello world", key)
        assert isinstance(ciphertext, bytes)
        assert ciphertext != b"hello world"

    def test_encrypt_same_plaintext_produces_different_ciphertext(self):
        """AES-GCM nonce ensures same plaintext -> different ciphertext."""
        key = derive_key("mypass", "mysalt")
        ct1 = encrypt_data(b"hello", key)
        ct2 = encrypt_data(b"hello", key)
        assert ct1 != ct2

    def test_decrypt_restores_original(self):
        """decrypt_data restores original plaintext."""
        key = derive_key("mypass", "mysalt")
        original = b"Hello, SSH Manager! This is test data."
        ciphertext = encrypt_data(original, key)
        plaintext = decrypt_data(ciphertext, key)
        assert plaintext == original

    def test_decrypt_wrong_key_raises(self):
        """Decrypting with wrong key raises CryptoError."""
        k1 = derive_key("pass1", "salt1")
        k2 = derive_key("pass2", "salt2")
        ciphertext = encrypt_data(b"secret", k1)
        with pytest.raises(CryptoError):
            decrypt_data(ciphertext, k2)

    def test_decrypt_corrupted_data_raises(self):
        """Decrypting corrupted/tampered ciphertext raises CryptoError."""
        key = derive_key("password", "salt")
        ciphertext = encrypt_data(b"secret", key)
        corrupted = ciphertext[:10] + b"x" + ciphertext[11:]
        with pytest.raises(CryptoError):
            decrypt_data(corrupted, key)

    def test_encrypt_decrypt_empty_data(self):
        """Empty data encrypt/decrypt round-trips."""
        key = derive_key("pw", "salt")
        ct = encrypt_data(b"", key)
        pt = decrypt_data(ct, key)
        assert pt == b""

    def test_encrypt_decrypt_unicode_data(self):
        """Unicode data round-trips correctly."""
        key = derive_key("pw", "salt")
        original = "你好，世界！配置内容包含中文。".encode("utf-8")
        ct = encrypt_data(original, key)
        pt = decrypt_data(ct, key)
        assert pt == original

    def test_encrypt_decrypt_large_data(self):
        """Large data (> 64KB) round-trips correctly."""
        key = derive_key("pw", "salt")
        original = b"x" * 128_000
        ct = encrypt_data(original, key)
        pt = decrypt_data(ct, key)
        assert pt == original
