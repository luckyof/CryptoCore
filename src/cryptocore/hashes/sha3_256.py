"""Потоковая реализация SHA3-256 по NIST FIPS 202."""

from typing import Union


BytesLike = Union[bytes, bytearray, memoryview]
_MASK64 = 0xFFFFFFFFFFFFFFFF

_ROUND_CONSTANTS = (
    0x0000000000000001, 0x0000000000008082,
    0x800000000000808A, 0x8000000080008000,
    0x000000000000808B, 0x0000000080000001,
    0x8000000080008081, 0x8000000000008009,
    0x000000000000008A, 0x0000000000000088,
    0x0000000080008009, 0x000000008000000A,
    0x000000008000808B, 0x800000000000008B,
    0x8000000000008089, 0x8000000000008003,
    0x8000000000008002, 0x8000000000000080,
    0x000000000000800A, 0x800000008000000A,
    0x8000000080008081, 0x8000000000008080,
    0x0000000080000001, 0x8000000080008008,
)

_ROTATION_OFFSETS = (
    (0, 36, 3, 41, 18),
    (1, 44, 10, 45, 2),
    (62, 6, 43, 15, 61),
    (28, 55, 25, 21, 56),
    (27, 20, 39, 8, 14),
)


def _rotate_left(value: int, amount: int) -> int:
    """Циклически сдвинуть 64-битное слово влево."""
    if amount == 0:
        return value & _MASK64
    return ((value << amount) | (value >> (64 - amount))) & _MASK64


def _as_bytes(data: BytesLike) -> bytes:
    if not isinstance(data, (bytes, bytearray, memoryview)):
        raise TypeError("данные для SHA3-256 должны быть байтовой последовательностью")
    return bytes(data)


def _keccak_f1600(state: list[int]) -> None:
    """Выполнить 24 раунда перестановки Keccak-f[1600]."""
    for round_constant in _ROUND_CONSTANTS:
        columns = [
            state[x] ^ state[x + 5] ^ state[x + 10] ^ state[x + 15] ^ state[x + 20]
            for x in range(5)
        ]
        differences = [
            columns[(x - 1) % 5] ^ _rotate_left(columns[(x + 1) % 5], 1)
            for x in range(5)
        ]
        for y in range(5):
            for x in range(5):
                state[x + 5 * y] ^= differences[x]

        rearranged = [0] * 25
        for y in range(5):
            for x in range(5):
                new_x = y
                new_y = (2 * x + 3 * y) % 5
                rearranged[new_x + 5 * new_y] = _rotate_left(
                    state[x + 5 * y], _ROTATION_OFFSETS[x][y]
                )

        for y in range(5):
            row = rearranged[5 * y:5 * y + 5]
            for x in range(5):
                state[x + 5 * y] = (
                    row[x] ^ ((~row[(x + 1) % 5]) & row[(x + 2) % 5])
                ) & _MASK64
        state[0] ^= round_constant


class SHA3_256:
    """Инкрементальный SHA3-256 на основе губчатой конструкции Keccak."""

    block_size = 136
    digest_size = 32
    name = "sha3_256"

    def __init__(self, data: BytesLike = b"") -> None:
        self._state = [0] * 25
        self._buffer = bytearray()
        if data:
            self.update(data)

    @staticmethod
    def _absorb_block(state: list[int], block: bytes) -> None:
        if len(block) != 136:
            raise ValueError("блок SHA3-256 должен содержать ровно 136 байт")
        for offset in range(0, 136, 8):
            state[offset // 8] ^= int.from_bytes(block[offset:offset + 8], "little")
        _keccak_f1600(state)

    def update(self, data: BytesLike) -> "SHA3_256":
        """Добавить очередную часть сообщения и вернуть текущий объект."""
        payload = _as_bytes(data)
        combined = bytes(self._buffer) + payload
        full_length = len(combined) - len(combined) % self.block_size
        for offset in range(0, full_length, self.block_size):
            self._absorb_block(self._state, combined[offset:offset + self.block_size])
        self._buffer = bytearray(combined[full_length:])
        return self

    def digest(self) -> bytes:
        """Вернуть 32 байта хеша, не изменяя инкрементальное состояние."""
        state = self._state.copy()
        padded = bytearray(self._buffer)
        padded.append(0x06)
        padded.extend(b"\x00" * (self.block_size - len(padded)))
        padded[-1] |= 0x80
        self._absorb_block(state, bytes(padded))

        output = bytearray()
        while len(output) < self.digest_size:
            for lane in state[:self.block_size // 8]:
                output.extend(lane.to_bytes(8, "little"))
            if len(output) < self.digest_size:
                _keccak_f1600(state)
        return bytes(output[:self.digest_size])

    def hexdigest(self) -> str:
        """Вернуть хеш в виде 64 hex-символов нижнего регистра."""
        return self.digest().hex()

    @classmethod
    def hash(cls, data: BytesLike) -> str:
        """Вычислить hex-хеш одной байтовой последовательности."""
        return cls(data).hexdigest()
