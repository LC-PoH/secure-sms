"""
app/utils/crypto.py — AES-256-GCM Field Encryption
===================================================
Provides authenticated encryption for sensitive PII stored in the database.

Algorithm:  AES-256-GCM (Advanced Encryption Standard, 256-bit key, Galois/Counter Mode)
            - 256-bit key (32 bytes)       → resists brute-force
            - 96-bit random nonce          → unique per encryption operation
            - GCM authentication tag       → detects tampered ciphertext
            - OWASP: "Use AES with at least 128-bit keys and authenticated modes (GCM)"

Storage format:  Base64URL( nonce[12] || ciphertext || auth_tag[16] )
"""

import os
import base64
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def encrypt_field(plaintext: str, key: bytes) -> str:
    """
    Encrypt a plaintext string using AES-256-GCM.

    :param plaintext: The sensitive value to encrypt (e.g. student name).
    :param key:       32-byte AES-256 key (from Config.ENCRYPTION_KEY).
    :returns:         Base64URL-encoded string: nonce + ciphertext + GCM-tag.
    :raises ValueError: if key is not 32 bytes.
    """
    if not plaintext:
        return plaintext
    if len(key) != 32:
        raise ValueError("AES-256 requires a 32-byte (256-bit) key.")

    aesgcm = AESGCM(key)
    nonce = os.urandom(12)   # 96-bit random nonce — MUST be unique per operation
    ciphertext_with_tag = aesgcm.encrypt(nonce, plaintext.encode('utf-8'), None)
    # Prepend nonce so it can be retrieved during decryption
    return base64.urlsafe_b64encode(nonce + ciphertext_with_tag).decode('utf-8')


def decrypt_field(encrypted: str, key: bytes) -> str:
    """
    Decrypt an AES-256-GCM encrypted field value.

    :param encrypted: Base64URL-encoded blob produced by encrypt_field().
    :param key:       32-byte AES-256 key (must match the encryption key).
    :returns:         Decrypted plaintext string.
    :raises Exception: if the ciphertext has been tampered with (GCM tag mismatch).
    """
    if not encrypted:
        return encrypted
    raw = base64.urlsafe_b64decode(encrypted.encode('utf-8'))
    nonce = raw[:12]
    ciphertext_with_tag = raw[12:]
    aesgcm = AESGCM(key)
    plaintext_bytes = aesgcm.decrypt(nonce, ciphertext_with_tag, None)
    return plaintext_bytes.decode('utf-8')
