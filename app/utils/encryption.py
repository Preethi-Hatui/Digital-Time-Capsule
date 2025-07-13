from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import base64


def pad(data: bytes) -> bytes:
    """Apply PKCS7 padding to binary data (multiple of AES block size)."""
    pad_len = AES.block_size - len(data) % AES.block_size
    return data + bytes([pad_len] * pad_len)


def unpad(data: bytes) -> bytes:
    """Remove PKCS7 padding from binary data."""
    pad_len = data[-1]
    if pad_len < 1 or pad_len > AES.block_size:
        raise ValueError("Invalid padding length")
    if data[-pad_len:] != bytes([pad_len] * pad_len):
        raise ValueError("Incorrect padding bytes")
    return data[:-pad_len]


def encrypt_file_aes(file_data: bytes, key: bytes) -> tuple[bytes, bytes]:
    """
    Encrypt binary file data using AES-CBC.

    Args:
        file_data: Raw bytes of the file.
        key: AES key (16/24/32 bytes).

    Returns:
        (encrypted_data, iv)
    """
    if not isinstance(file_data, bytes):
        raise TypeError("File data must be bytes")
    if not isinstance(key, bytes) or len(key) not in {16, 24, 32}:
        raise ValueError("Key must be 16, 24, or 32 bytes")

    iv = get_random_bytes(AES.block_size)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded = pad(file_data)
    encrypted = cipher.encrypt(padded)
    return encrypted, iv


def decrypt_file_aes(encrypted_data: bytes, key: bytes, iv: bytes) -> bytes:
    """
    Decrypt AES-CBC encrypted binary data.

    Args:
        encrypted_data: Encrypted bytes.
        key: AES key.
        iv: Initialization vector used for encryption.

    Returns:
        Decrypted file bytes.
    """
    if not all(isinstance(i, bytes) for i in (encrypted_data, key, iv)):
        raise TypeError("All inputs must be bytes")
    if len(iv) != AES.block_size:
        raise ValueError("IV must be 16 bytes")

    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded = cipher.decrypt(encrypted_data)
    return unpad(padded)
