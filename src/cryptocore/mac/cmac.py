"""Собственный потоковый AES-128-CMAC по NIST SP 800-38B."""

from Crypto.Cipher import AES

from cryptocore.errors import InvalidKeyError
from cryptocore.hashes.sha256 import BytesLike
from cryptocore.modes.ecb import _validate_key


def _xor(left: bytes, right: bytes) -> bytes:
    return bytes(a ^ b for a, b in zip(left, right))


def _double(block: bytes) -> bytes:
    """Удвоить 128-битный блок в GF(2^128), используя Rb = 0x87."""
    value = int.from_bytes(block, "big")
    doubled = ((value << 1) & ((1 << 128) - 1)) ^ (0x87 & -(value >> 127))
    return doubled.to_bytes(16, "big")


class CMAC:
    """CBC-MAC с подключами K1/K2; готовый CMAC библиотеки не используется."""

    block_size = 16
    digest_size = 16
    name = "aes-128-cmac"

    def __init__(self, key: BytesLike) -> None:
        if not isinstance(key, (bytes, bytearray, memoryview)):
            raise InvalidKeyError("ключ AES-CMAC должен быть передан как байты")
        self._key = bytes(key)
        _validate_key(self._key)
        self._cipher = AES.new(self._key, AES.MODE_ECB)
        self._k1 = _double(self._cipher.encrypt(bytes(16)))
        self._k2 = _double(self._k1)
        self._state = bytes(16)
        self._buffer = b""

    def update(self, data: BytesLike) -> "CMAC":
        """Обработать блоки, оставив последний блок для выбора K1 либо K2."""
        if not isinstance(data, (bytes, bytearray, memoryview)):
            raise TypeError("данные CMAC должны быть байтовой последовательностью")
        combined = self._buffer + bytes(data)
        full = max(0, (len(combined) - 1) // self.block_size * self.block_size)
        state = self._state
        for offset in range(0, full, self.block_size):
            state = self._cipher.encrypt(_xor(state, combined[offset:offset + self.block_size]))
        self._state = state
        self._buffer = combined[full:]
        return self

    def digest(self) -> bytes:
        """Вернуть полный тег, не изменяя состояние и не завершая поток."""
        if len(self._buffer) == self.block_size:
            last = _xor(self._buffer, self._k1)
        else:
            # Пустое сообщение также использует K2 и дополнение 0x80 || 0*.
            padded = self._buffer + b"\x80" + bytes(15 - len(self._buffer))
            last = _xor(padded, self._k2)
        return self._cipher.encrypt(_xor(self._state, last))

    def hexdigest(self) -> str:
        """Вернуть 32 hex-символа нижнего регистра."""
        return self.digest().hex()

    def compute(self, message: BytesLike) -> str:
        """Вычислить тег отдельного сообщения с тем же ключом."""
        return CMAC(self._key).update(message).hexdigest()


def cmac_aes(key: BytesLike, data: BytesLike) -> bytes:
    """Вычислить полный 128-битный AES-CMAC одной последовательности байтов."""
    return CMAC(key).update(data).digest()
