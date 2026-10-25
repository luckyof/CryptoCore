"""Потоковый HMAC-SHA256 по RFC 2104, без готовой реализации HMAC."""

from cryptocore.hashes import SHA256
from cryptocore.hashes.sha256 import BytesLike


def _bytes(data: BytesLike) -> bytes:
    if not isinstance(data, (bytes, bytearray, memoryview)):
        raise TypeError("ключ и данные HMAC должны быть байтовой последовательностью")
    return bytes(data)


class HMAC:
    """Инкрементальный HMAC поверх собственной реализации SHA-256."""

    block_size = 64
    digest_size = 32
    name = "hmac-sha256"

    def __init__(self, key: BytesLike, hash_function: str = "sha256") -> None:
        if hash_function != "sha256":
            raise ValueError("HMAC поддерживает только алгоритм sha256")
        normalized = _bytes(key)
        if len(normalized) > self.block_size:
            normalized = SHA256(normalized).digest()
        self._key_block = normalized.ljust(self.block_size, b"\x00")
        self._opad = bytes(byte ^ 0x5C for byte in self._key_block)
        self._inner_template = SHA256(bytes(byte ^ 0x36 for byte in self._key_block))
        self._outer_template = SHA256(self._opad)
        self._inner = self._inner_template.copy()

    def update(self, data: BytesLike) -> "HMAC":
        """Добавить фрагмент сообщения без накопления всего сообщения."""
        self._inner.update(_bytes(data))
        return self

    def digest(self) -> bytes:
        """Получить полный 32-байтный тег, не изменяя потоковое состояние."""
        outer = self._outer_template.copy()
        outer.update(self._inner.digest())
        return outer.digest()

    def hexdigest(self) -> str:
        """Получить тег в виде 64 hex-символов нижнего регистра."""
        return self.digest().hex()

    def compute(self, message: BytesLike) -> str:
        """Вычислить тег отдельного сообщения с тем же ключом."""
        return self.digest_message(message).hex()

    def digest_message(self, message: BytesLike) -> bytes:
        """Вычислить отдельный HMAC с предвычисленными ipad/opad для PBKDF2."""
        inner = self._inner_template.copy()
        inner.update(_bytes(message))
        outer = self._outer_template.copy()
        outer.update(inner.digest())
        return outer.digest()


def hmac_sha256(key: BytesLike, data: BytesLike) -> bytes:
    """Одноразовый интерфейс, совместимый с аутентифицированными режимами."""
    return HMAC(key).update(data).digest()
