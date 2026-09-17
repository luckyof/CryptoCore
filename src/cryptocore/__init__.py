"""Публичный пакет CryptoCore."""

from .modes.ecb import decrypt_ecb, encrypt_ecb

__all__ = ["decrypt_ecb", "encrypt_ecb"]
__version__ = "0.1.0"
