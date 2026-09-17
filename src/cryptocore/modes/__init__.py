"""Режимы блочного шифрования, реализованные в CryptoCore."""

from .ecb import decrypt_ecb, encrypt_ecb

__all__ = ["decrypt_ecb", "encrypt_ecb"]
