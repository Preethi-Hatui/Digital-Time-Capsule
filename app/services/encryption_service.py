import os
from typing import Tuple, Optional
from flask import current_app
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding, hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, RSAPublicKey


class EncryptionService:
    @staticmethod
    def generate_aes_key() -> bytes:
        """
        Generate a secure 256-bit AES key (32 bytes).
        """
        return os.urandom(32)

    @staticmethod
    def encrypt_file_aes(plaintext_data: bytes, key: bytes) -> Tuple[bytes, bytes]:
        """
        Encrypts data using AES-256-CBC with PKCS7 padding.

        Args:
            plaintext_data: Raw file content as bytes.
            key: 32-byte AES key.

        Returns:
            Tuple (encrypted_data, iv)
        """
        if len(key) != 32:
            raise ValueError("AES key must be 32 bytes (256 bits)")

        iv = os.urandom(16)
        padder = padding.PKCS7(128).padder()
        padded_data = padder.update(plaintext_data) + padder.finalize()

        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        encrypted_data = encryptor.update(padded_data) + encryptor.finalize()

        return encrypted_data, iv

    @staticmethod
    def decrypt_file_aes(encrypted_data: bytes, key: bytes, iv: bytes) -> Optional[bytes]:
        """
        Decrypts AES-256-CBC encrypted data with PKCS7 unpadding.

        Args:
            encrypted_data: Encrypted file content.
            key: 32-byte AES key.
            iv: Initialization vector used during encryption.

        Returns:
            Decrypted file content, or None if decryption fails.
        """
        try:
            if len(key) != 32:
                raise ValueError("AES key must be 32 bytes (256 bits)")

            cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
            decryptor = cipher.decryptor()
            padded_data = decryptor.update(encrypted_data) + decryptor.finalize()

            unpadder = padding.PKCS7(128).unpadder()
            return unpadder.update(padded_data) + unpadder.finalize()

        except Exception as e:
            current_app.logger.error(f"[EncryptionService] AES decryption error: {e}")
            return None

    @staticmethod
    def encrypt_aes_key_with_rsa(aes_key: bytes, public_key: RSAPublicKey) -> bytes:
        """
        Encrypts an AES key using RSA public key with OAEP + SHA-256.

        Args:
            aes_key: AES key to encrypt.
            public_key: RSA public key instance.

        Returns:
            RSA-encrypted AES key.
        """
        return public_key.encrypt(
            aes_key,
            asym_padding.OAEP(
                mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

    @staticmethod
    def decrypt_aes_key_with_rsa(encrypted_key: bytes, private_key: RSAPrivateKey) -> Optional[bytes]:
        """
        Decrypts RSA-encrypted AES key using RSA private key.

        Args:
            encrypted_key: AES key encrypted with RSA.
            private_key: RSA private key instance.

        Returns:
            Decrypted AES key, or None on failure.
        """
        try:
            return private_key.decrypt(
                encrypted_key,
                asym_padding.OAEP(
                    mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
        except Exception as e:
            current_app.logger.error(f"[EncryptionService] RSA decryption error: {e}")
            return None
