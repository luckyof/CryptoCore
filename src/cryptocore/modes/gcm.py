"""AES-128 GCM: потоковый GHASH и собственный CTR по NIST SP 800-38D."""

from hmac import compare_digest
from typing import BinaryIO, Iterable, Union

from Crypto.Cipher import AES

from cryptocore.errors import AuthenticationError, CryptoCoreError
from cryptocore.csprng import generate_random_bytes
from .ecb import _validate_key
from .feedback import _xor


AUTH_ERROR = "аутентификация не пройдена: неверный ключ, AAD или повреждённые данные"
MAX_DATA_SIZE = (1 << 36) - 32
MAX_AAD_SIZE = (1 << 61) - 1
AADSource = Union[bytes, bytearray, memoryview, BinaryIO, Iterable[bytes]]
_REDUCTION = 0xE1000000000000000000000000000000


def _bytes(data) -> bytes:
    if not isinstance(data, (bytes, bytearray, memoryview)):
        raise CryptoCoreError("данные GCM/AAD должны быть байтовой последовательностью")
    return bytes(data)


def iter_aad(source: AADSource):
    """Читать AAD по частям; поток и итератор потребляются ровно один раз."""
    if isinstance(source, (bytes, bytearray, memoryview)):
        view = memoryview(source).cast("B")
        for offset in range(0, len(view), 8192):
            yield bytes(view[offset:offset + 8192])
    elif hasattr(source, "read"):
        while True:
            chunk = source.read(8192)
            if chunk == b"":
                break
            yield _bytes(chunk)
    else:
        try:
            iterator = iter(source)
        except TypeError as error:
            raise CryptoCoreError("AAD должен быть байтами, бинарным потоком или итератором фрагментов") from error
        for chunk in iterator:
            yield _bytes(chunk)


def _multiply(left: int, right: int) -> int:
    """Умножить элементы GF(2^128) с полиномом x^128+x^7+x^2+x+1."""
    result = 0
    for bit in range(127, -1, -1):
        result ^= right & -((left >> bit) & 1)
        right = (right >> 1) ^ (_REDUCTION & -(right & 1))
    return result


def _shift8(value: int) -> int:
    for _ in range(8):
        value = (value >> 1) ^ (_REDUCTION & -(value & 1))
    return value


_REDUCE8 = tuple(_shift8(value) for value in range(256))


class GHASH:
    """Инкрементальный GHASH с таблицей 256 значений для фиксированного H."""

    def __init__(self, hash_key: int) -> None:
        basis = []
        for _ in range(8):
            basis.append(hash_key)
            hash_key = (hash_key >> 1) ^ (_REDUCTION & -(hash_key & 1))
        table = []
        for byte in range(256):
            value = 0
            for bit in range(8):
                value ^= basis[bit] & -((byte >> (7 - bit)) & 1)
            table.append(value)
        self._table = tuple(table)
        self._state = 0
        self._buffer = b""

    def multiply(self, value: int) -> int:
        result = 0
        # Низшие байты обрабатываются первыми; сдвиг редуцируется по полиному.
        for _ in range(16):
            result = (result >> 8) ^ _REDUCE8[result & 0xFF] ^ self._table[value & 0xFF]
            value >>= 8
        return result

    def update(self, data: bytes) -> None:
        combined = self._buffer + _bytes(data)
        full = len(combined) - len(combined) % 16
        state = self._state
        for offset in range(0, full, 16):
            state = self.multiply(state ^ int.from_bytes(combined[offset:offset + 16], "big"))
        self._state = state
        self._buffer = combined[full:]

    def pad(self) -> None:
        """Дополнить только текущую секцию AAD/шифротекста, не каждый фрагмент."""
        if self._buffer:
            self.update(bytes(16 - len(self._buffer)))

    def digest(self) -> bytes:
        self.pad()
        return self._state.to_bytes(16, "big")


def _ghash(hash_key: int, aad: bytes, ciphertext: bytes) -> bytes:
    hasher = GHASH(hash_key)
    for section in (aad, ciphertext):
        hasher.update(section)
        hasher.pad()
    hasher.update((len(aad) * 8).to_bytes(8, "big") + (len(ciphertext) * 8).to_bytes(8, "big"))
    return hasher.digest()


class GCMAuthenticator:
    """Накопить AAD и шифротекст, проверить тег без расшифрования."""

    def __init__(self, key: bytes, nonce: bytes) -> None:
        _validate_key(key)
        nonce = _bytes(nonce)
        if not nonce or len(nonce) > MAX_AAD_SIZE:
            raise CryptoCoreError("nonce GCM должен быть непустым и иметь допустимую длину")
        self.cipher = AES.new(key, AES.MODE_ECB)
        hash_key = int.from_bytes(self.cipher.encrypt(bytes(16)), "big")
        self.initial = nonce + b"\x00\x00\x00\x01" if len(nonce) == 12 else _ghash(hash_key, b"", nonce)
        self._ghash = GHASH(hash_key)
        self._aad_size = 0
        self._data_size = 0
        self._data_started = False
        self._tag = None

    def update_aad(self, data: bytes) -> None:
        if self._data_started or self._tag is not None:
            raise CryptoCoreError("AAD должен поступать до шифротекста и завершения GCM")
        data = _bytes(data)
        if self._aad_size + len(data) > MAX_AAD_SIZE:
            raise CryptoCoreError("превышена допустимая длина AAD для GCM")
        self._aad_size += len(data)
        self._ghash.update(data)

    def update_ciphertext(self, data: bytes) -> None:
        if self._tag is not None:
            raise CryptoCoreError("аутентификация GCM уже завершена")
        data = _bytes(data)
        if self._data_size + len(data) > MAX_DATA_SIZE:
            raise CryptoCoreError("превышен предел GCM: 2^32-2 блока на один nonce")
        if not self._data_started:
            self._ghash.pad()
            self._data_started = True
        self._data_size += len(data)
        self._ghash.update(data)

    def digest(self) -> bytes:
        if self._tag is None:
            self.update_ciphertext(b"")
            self._ghash.pad()
            self._ghash.update((self._aad_size * 8).to_bytes(8, "big")
                               + (self._data_size * 8).to_bytes(8, "big"))
            self._tag = _xor(self.cipher.encrypt(self.initial), self._ghash.digest())
        return self._tag

    def verify(self, tag: bytes) -> None:
        if len(tag) != 16 or not compare_digest(self.digest(), tag):
            raise AuthenticationError(AUTH_ERROR)


def feed_aad(authenticator: GCMAuthenticator, aad: AADSource) -> None:
    for chunk in iter_aad(aad):
        authenticator.update_aad(chunk)


class GCTR:
    """CTR GCM с сохранением остатка гаммы между произвольными фрагментами."""

    def __init__(self, cipher, initial: bytes) -> None:
        self._cipher = cipher
        self._prefix = initial[:12]
        self._counter = int.from_bytes(initial[12:], "big")
        self._gamma = b""
        self._size = 0

    def transform(self, data: bytes) -> bytes:
        data = _bytes(data)
        if self._size + len(data) > MAX_DATA_SIZE:
            raise CryptoCoreError("превышен предел GCM: 2^32-2 блока на один nonce")
        self._size += len(data)
        result = bytearray()
        offset = 0
        while offset < len(data):
            if not self._gamma:
                self._counter = (self._counter + 1) & 0xFFFFFFFF
                self._gamma = self._cipher.encrypt(self._prefix + self._counter.to_bytes(4, "big"))
            size = min(len(self._gamma), len(data) - offset)
            result.extend(_xor(data[offset:offset + size], self._gamma[:size]))
            self._gamma = self._gamma[size:]
            offset += size
        return bytes(result)


def _transform(cipher, initial: bytes, data: bytes) -> bytes:
    return GCTR(cipher, initial).transform(data)


def encrypt_gcm(plaintext: bytes, key: bytes, nonce: bytes, aad: AADSource = b"") -> bytes:
    """Вернуть шифротекст и 16-байтный тег для заданного nonce."""
    auth = GCMAuthenticator(key, nonce)
    feed_aad(auth, aad)
    ciphertext = _transform(auth.cipher, auth.initial, plaintext)
    auth.update_ciphertext(ciphertext)
    return ciphertext + auth.digest()


def decrypt_gcm(data: bytes, key: bytes, nonce: bytes, aad: AADSource = b"") -> bytes:
    """Проверить тег до расшифрования и возврата открытого текста."""
    if len(data) < 16:
        raise AuthenticationError(AUTH_ERROR)
    ciphertext, tag = data[:-16], data[-16:]
    auth = GCMAuthenticator(key, nonce)
    feed_aad(auth, aad)
    auth.update_ciphertext(ciphertext)
    auth.verify(tag)
    return _transform(auth.cipher, auth.initial, ciphertext)


class GCM:
    """Общий AEAD API: nonce ∥ ciphertext ∥ tag; свежий nonce при шифровании."""

    def __init__(self, key: bytes, nonce: bytes = None) -> None:
        _validate_key(key)
        if nonce is not None and (not isinstance(nonce, bytes) or not nonce):
            raise CryptoCoreError("nonce GCM должен быть непустой байтовой последовательностью")
        self._key = key
        self.nonce = nonce
        self._explicit_nonce = nonce is not None
        self._used = False

    def encrypt(self, plaintext: bytes, aad: AADSource = b"") -> bytes:
        if self._explicit_nonce and self._used:
            raise CryptoCoreError("нельзя повторно шифровать GCM с явно заданным nonce")
        if not self._explicit_nonce:
            self.nonce = generate_random_bytes(12)
        self._used = True
        return self.nonce + encrypt_gcm(plaintext, self._key, self.nonce, aad)

    def decrypt(self, data: bytes, aad: AADSource = b"") -> bytes:
        size = len(self.nonce) if self._explicit_nonce else 12
        if len(data) < size + 16:
            raise AuthenticationError(AUTH_ERROR)
        nonce = data[:size]
        if self._explicit_nonce and nonce != self.nonce:
            raise AuthenticationError(AUTH_ERROR)
        result = decrypt_gcm(data[size:], self._key, nonce, aad)
        self.nonce = nonce
        return result
