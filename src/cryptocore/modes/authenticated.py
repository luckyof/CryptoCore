"""Encrypt-then-MAC для CBC и сегментированного CTR с ротацией nonce."""

from hmac import compare_digest
import struct

from Crypto.Cipher import AES

from cryptocore.authentication import derive_keys, hmac_sha256
from cryptocore.csprng import generate_random_bytes
from cryptocore.errors import AuthenticationError, CryptoCoreError
from .ecb import _validate_key
from .feedback import encrypt_cbc, decrypt_cbc, _xor
from .gcm import AUTH_ERROR


CBC_MAGIC = b"CCBC\x01"
CTR_MAGIC = b"CCTR\x01"
DEFAULT_SEGMENT_SIZE = 1024 * 1024
MAX_SEGMENT_SIZE = 64 * 1024 * 1024


def _mac(key: bytes, body: bytes, aad: bytes) -> bytes:
    return hmac_sha256(key, len(aad).to_bytes(8, "big") + aad + body)


def encrypt_cbc_hmac(data: bytes, key: bytes, iv: bytes, aad: bytes = b"") -> bytes:
    """Аутентифицировать версию формата, IV, шифротекст и AAD."""
    encryption, authentication = derive_keys(key, CBC_MAGIC)
    body = CBC_MAGIC + iv + encrypt_cbc(data, encryption, iv)
    return body + _mac(authentication, body, aad)


def decrypt_cbc_hmac(data: bytes, key: bytes, aad: bytes = b"") -> bytes:
    """Проверить MAC до AES и padding; все отказы имеют общую ошибку."""
    encryption, authentication = derive_keys(key, CBC_MAGIC)
    if len(data) < len(CBC_MAGIC) + 16 + 16 + 32:
        raise AuthenticationError(AUTH_ERROR)
    body, tag = data[:-32], data[-32:]
    if not compare_digest(tag, _mac(authentication, body, aad)) or not body.startswith(CBC_MAGIC):
        raise AuthenticationError(AUTH_ERROR)
    try:
        return decrypt_cbc(body[21:], encryption, body[5:21])
    except CryptoCoreError as error:
        raise AuthenticationError(AUTH_ERROR) from error


def transform_ctr_nonce(data: bytes, key: bytes, nonce: bytes, initial_counter: int = 0) -> bytes:
    """CTR с фиксированным 96-битным nonce и отдельным 32-битным счётчиком."""
    _validate_key(key)
    if not isinstance(nonce, bytes) or len(nonce) != 12:
        raise CryptoCoreError("nonce CTR должен содержать ровно 12 байт")
    if not isinstance(initial_counter, int) or isinstance(initial_counter, bool) or not 0 <= initial_counter < 1 << 32:
        raise CryptoCoreError("начальный счётчик CTR должен быть 32-битным целым числом")
    blocks = (len(data) + 15) // 16
    if blocks > (1 << 32) - initial_counter:
        raise CryptoCoreError("исчерпан счётчик CTR: требуется новый nonce")
    cipher = AES.new(key, AES.MODE_ECB)
    result = bytearray()
    for index, offset in enumerate(range(0, len(data), 16)):
        block = nonce + (initial_counter + index).to_bytes(4, "big")
        result.extend(_xor(data[offset:offset + 16], cipher.encrypt(block)))
    return bytes(result)


def _segment_size(size: int) -> None:
    if not isinstance(size, int) or isinstance(size, bool) or not 1 <= size <= MAX_SEGMENT_SIZE:
        raise CryptoCoreError(f"размер сегмента CTR должен быть от 1 до {MAX_SEGMENT_SIZE} байт")


def encrypt_ctr_hmac(data: bytes, key: bytes, aad: bytes = b"", segment_size: int = DEFAULT_SEGMENT_SIZE) -> bytes:
    """Менять nonce между сегментами; MAC связывает порядок, длину и заголовок."""
    _segment_size(segment_size)
    encryption, authentication = derive_keys(key, CTR_MAGIC)
    header = CTR_MAGIC + struct.pack(">IQ", segment_size, len(data))
    result = bytearray(header + _mac(authentication, header, aad))
    used_nonces = set()
    count = (len(data) + segment_size - 1) // segment_size
    if count > 1 << 32:
        raise CryptoCoreError("слишком много сегментов CTR: требуется новый файл и ключ")
    for index, offset in enumerate(range(0, len(data), segment_size)):
        for attempt in range(8):
            nonce = generate_random_bytes(12)
            if nonce not in used_nonces:
                break
        else:
            raise CryptoCoreError("повтор nonce CTR: источник случайности неисправен")
        used_nonces.add(nonce)
        ciphertext = transform_ctr_nonce(data[offset:offset + segment_size], encryption, nonce)
        record = nonce + ciphertext
        tag = _mac(authentication, header + index.to_bytes(4, "big") + record, aad)
        result.extend(record + tag)
    return bytes(result)


def decrypt_ctr_hmac(data: bytes, key: bytes, aad: bytes = b"") -> bytes:
    """Проверить заголовок и все теги до расшифрования любых сегментов."""
    encryption, authentication = derive_keys(key, CTR_MAGIC)
    if len(data) < 49:
        raise AuthenticationError(AUTH_ERROR)
    header, tag = data[:17], data[17:49]
    if not compare_digest(tag, _mac(authentication, header, aad)) or not header.startswith(CTR_MAGIC):
        raise AuthenticationError(AUTH_ERROR)
    segment_size, total = struct.unpack(">IQ", header[5:])
    try:
        _segment_size(segment_size)
    except CryptoCoreError as error:
        raise AuthenticationError(AUTH_ERROR) from error
    count = (total + segment_size - 1) // segment_size
    if count > 1 << 32 or len(data) != 49 + total + count * 44:
        raise AuthenticationError(AUTH_ERROR)
    offset = 49
    for index in range(count):
        size = min(segment_size, total - index * segment_size)
        record = data[offset:offset + 12 + size]
        tag = data[offset + 12 + size:offset + 44 + size]
        expected = _mac(authentication, header + index.to_bytes(4, "big") + record, aad)
        if not compare_digest(tag, expected):
            raise AuthenticationError(AUTH_ERROR)
        offset += size + 44
    result = bytearray()
    offset = 49
    for index in range(count):
        size = min(segment_size, total - index * segment_size)
        nonce = data[offset:offset + 12]
        result.extend(transform_ctr_nonce(data[offset + 12:offset + 12 + size], encryption, nonce))
        offset += size + 44
    return bytes(result)
