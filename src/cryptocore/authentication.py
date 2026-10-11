"""HMAC-SHA256 и разделение ключей для аутентифицированных форматов."""

from .mac.hmac import hmac_sha256
from .modes.ecb import _validate_key


def derive_keys(master_key: bytes, domain: bytes):
    """Получить разные ключи AES и MAC с разделением по назначению и формату."""
    _validate_key(master_key)
    encryption = hmac_sha256(master_key, domain + b"/encryption")[:16]
    authentication = hmac_sha256(master_key, domain + b"/authentication")
    return encryption, authentication
