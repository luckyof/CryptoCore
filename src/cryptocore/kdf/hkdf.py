"""Иерархия ключей по формуле задания; это не HKDF из RFC 5869."""

from cryptocore.mac import HMAC
from .pbkdf2 import as_bytes, validate_length


def derive_key(master_key: bytes, context: str, length: int = 32) -> bytes:
    """Объединить HMAC(master_key, UTF8(context) ∥ INT_32_BE(counter))."""
    validate_length(length)
    master_key = as_bytes(master_key, "master key")
    if not master_key:
        raise ValueError("master key не должен быть пустым")
    if not isinstance(context, str) or not context:
        raise ValueError("контекст ключа должен быть непустой строкой")
    encoded = context.encode("utf-8")
    mac = HMAC(master_key)
    result = bytearray()
    for counter in range(1, (length + 31) // 32 + 1):
        result.extend(mac.digest_message(encoded + counter.to_bytes(4, "big")))
    return bytes(result[:length])
