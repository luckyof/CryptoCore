"""Получение ключей из паролей и разделение ключей по назначению."""

from .pbkdf2 import pbkdf2_hmac_sha256
from .hkdf import derive_key

__all__ = ["pbkdf2_hmac_sha256", "derive_key"]
