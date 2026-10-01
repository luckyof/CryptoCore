"""AES-128 GCM: собственные GHASH и CTR по NIST SP 800-38D."""

from hmac import compare_digest

from Crypto.Cipher import AES

from cryptocore.errors import AuthenticationError, CryptoCoreError
from .ecb import _validate_key
from .feedback import _xor


AUTH_ERROR = "аутентификация не пройдена: неверный ключ, AAD или повреждённые данные"


def _multiply(left: int, right: int) -> int:
    """Умножить элементы GF(2^128) с полиномом x^128+x^7+x^2+x+1."""
    result = 0
    for bit in range(127, -1, -1):
        result ^= right & -((left >> bit) & 1)
        right = (right >> 1) ^ (0xE1000000000000000000000000000000 & -(right & 1))
    return result


def _ghash(hash_key: int, aad: bytes, ciphertext: bytes) -> bytes:
    state = 0
    for data in (aad, ciphertext):
        for offset in range(0, len(data), 16):
            block = data[offset:offset + 16].ljust(16, b"\x00")
            state = _multiply(state ^ int.from_bytes(block, "big"), hash_key)
    lengths = (len(aad) * 8).to_bytes(8, "big") + (len(ciphertext) * 8).to_bytes(8, "big")
    state = _multiply(state ^ int.from_bytes(lengths, "big"), hash_key)
    return state.to_bytes(16, "big")


def _parameters(key: bytes, nonce: bytes, aad: bytes, size: int):
    _validate_key(key)
    if not isinstance(nonce, bytes) or not nonce:
        raise CryptoCoreError("nonce GCM должен быть непустой байтовой последовательностью")
    if len(nonce) >= 1 << 61 or len(aad) >= 1 << 61:
        raise CryptoCoreError("превышена допустимая длина nonce или AAD для GCM")
    if size > (1 << 36) - 32:
        raise CryptoCoreError("превышен предел GCM: 2^32-2 блока на один nonce")
    cipher = AES.new(key, AES.MODE_ECB)
    hash_key = int.from_bytes(cipher.encrypt(b"\x00" * 16), "big")
    initial = nonce + b"\x00\x00\x00\x01" if len(nonce) == 12 else _ghash(hash_key, b"", nonce)
    return cipher, hash_key, initial


def _transform(cipher, initial: bytes, data: bytes) -> bytes:
    prefix = initial[:12]
    counter = int.from_bytes(initial[12:], "big")
    result = bytearray()
    for offset in range(0, len(data), 16):
        counter = (counter + 1) & 0xFFFFFFFF
        gamma = cipher.encrypt(prefix + counter.to_bytes(4, "big"))
        result.extend(_xor(data[offset:offset + 16], gamma))
    return bytes(result)


def encrypt_gcm(plaintext: bytes, key: bytes, nonce: bytes, aad: bytes = b"") -> bytes:
    """Вернуть шифротекст и 16-байтный тег для заданного nonce."""
    cipher, hash_key, initial = _parameters(key, nonce, aad, len(plaintext))
    ciphertext = _transform(cipher, initial, plaintext)
    tag = _xor(cipher.encrypt(initial), _ghash(hash_key, aad, ciphertext))
    return ciphertext + tag


def decrypt_gcm(data: bytes, key: bytes, nonce: bytes, aad: bytes = b"") -> bytes:
    """Проверить тег до расшифрования и возврата открытого текста."""
    if len(data) < 16:
        raise AuthenticationError(AUTH_ERROR)
    ciphertext, tag = data[:-16], data[-16:]
    cipher, hash_key, initial = _parameters(key, nonce, aad, len(ciphertext))
    expected = _xor(cipher.encrypt(initial), _ghash(hash_key, aad, ciphertext))
    if not compare_digest(tag, expected):
        raise AuthenticationError(AUTH_ERROR)
    return _transform(cipher, initial, ciphertext)
