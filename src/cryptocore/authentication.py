"""HMAC-SHA256 и разделение ключей для аутентифицированных форматов."""

from .hashes import SHA256
from .modes.ecb import _validate_key


def hmac_sha256(key: bytes, data: bytes) -> bytes:
    """Вычислить HMAC поверх собственной потоковой реализации SHA-256."""
    if len(key) > 64:
        key = SHA256(key).digest()
    key = key.ljust(64, b"\x00")
    inner = SHA256(bytes(byte ^ 0x36 for byte in key))
    inner.update(data)
    outer = SHA256(bytes(byte ^ 0x5C for byte in key))
    outer.update(inner.digest())
    return outer.digest()


def derive_keys(master_key: bytes, domain: bytes):
    """Получить разные ключи AES и MAC с разделением по назначению и формату."""
    _validate_key(master_key)
    encryption = hmac_sha256(master_key, domain + b"/encryption")[:16]
    authentication = hmac_sha256(master_key, domain + b"/authentication")
    return encryption, authentication
