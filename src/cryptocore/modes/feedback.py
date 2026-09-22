"""Ручные режимы CBC, CFB-128, OFB и CTR поверх блочного AES."""

from Crypto.Cipher import AES
from cryptocore.errors import CryptoCoreError, InvalidCiphertextError
from .ecb import BLOCK_SIZE, _validate_key, _pkcs7_pad, _pkcs7_unpad


def _cipher(key: bytes, iv: bytes):
    _validate_key(key)
    if not isinstance(iv, bytes) or len(iv) != BLOCK_SIZE:
        raise CryptoCoreError("IV должен содержать ровно 16 байт")
    return AES.new(key, AES.MODE_ECB)


def _xor(left: bytes, right: bytes) -> bytes:
    """XOR с сохранением длины неполного последнего блока."""
    return bytes(a ^ b for a, b in zip(left, right))


def encrypt_cbc(plaintext: bytes, key: bytes, iv: bytes) -> bytes:
    """Зашифровать CBC с дополнением PKCS#7."""
    cipher = _cipher(key, iv)
    data = _pkcs7_pad(plaintext)
    result = bytearray()
    previous = iv
    for offset in range(0, len(data), BLOCK_SIZE):
        previous = cipher.encrypt(_xor(data[offset:offset + BLOCK_SIZE], previous))
        result.extend(previous)
    return bytes(result)


def decrypt_cbc(ciphertext: bytes, key: bytes, iv: bytes) -> bytes:
    """Расшифровать CBC и проверить дополнение."""
    cipher = _cipher(key, iv)
    if not ciphertext or len(ciphertext) % BLOCK_SIZE:
        raise InvalidCiphertextError("шифротекст CBC должен быть непустым и кратным 16 байтам")
    result = bytearray()
    previous = iv
    for offset in range(0, len(ciphertext), BLOCK_SIZE):
        block = ciphertext[offset:offset + BLOCK_SIZE]
        result.extend(_xor(cipher.decrypt(block), previous))
        previous = block
    return _pkcs7_unpad(bytes(result))


def _cfb(data: bytes, key: bytes, iv: bytes, decrypting: bool) -> bytes:
    cipher = _cipher(key, iv)
    result = bytearray()
    feedback = iv
    for offset in range(0, len(data), BLOCK_SIZE):
        block = data[offset:offset + BLOCK_SIZE]
        transformed = _xor(block, cipher.encrypt(feedback))
        result.extend(transformed)
        feedback = block if decrypting else transformed
    return bytes(result)


def encrypt_cfb(plaintext: bytes, key: bytes, iv: bytes) -> bytes:
    """Зашифровать CFB-128 без дополнения."""
    return _cfb(plaintext, key, iv, False)


def decrypt_cfb(ciphertext: bytes, key: bytes, iv: bytes) -> bytes:
    """Расшифровать CFB-128 без дополнения."""
    return _cfb(ciphertext, key, iv, True)


def encrypt_ofb(data: bytes, key: bytes, iv: bytes) -> bytes:
    """Преобразовать данные гаммой OFB."""
    cipher = _cipher(key, iv)
    result = bytearray()
    feedback = iv
    for offset in range(0, len(data), BLOCK_SIZE):
        feedback = cipher.encrypt(feedback)
        result.extend(_xor(data[offset:offset + BLOCK_SIZE], feedback))
    return bytes(result)


def decrypt_ofb(ciphertext: bytes, key: bytes, iv: bytes) -> bytes:
    """Расшифровать OFB."""
    return encrypt_ofb(ciphertext, key, iv)


def encrypt_ctr(data: bytes, key: bytes, iv: bytes) -> bytes:
    """CTR: 128-битный счётчик big-endian, инкремент по модулю 2**128."""
    cipher = _cipher(key, iv)
    counter = int.from_bytes(iv, "big")
    result = bytearray()
    for offset in range(0, len(data), BLOCK_SIZE):
        gamma = cipher.encrypt(counter.to_bytes(BLOCK_SIZE, "big"))
        result.extend(_xor(data[offset:offset + BLOCK_SIZE], gamma))
        counter = (counter + 1) % (1 << 128)
    return bytes(result)


def decrypt_ctr(ciphertext: bytes, key: bytes, iv: bytes) -> bytes:
    """Расшифровать CTR."""
    return encrypt_ctr(ciphertext, key, iv)


MODES = {
    "cbc": (encrypt_cbc, decrypt_cbc),
    "cfb": (encrypt_cfb, decrypt_cfb),
    "ofb": (encrypt_ofb, decrypt_ofb),
    "ctr": (encrypt_ctr, decrypt_ctr),
}
