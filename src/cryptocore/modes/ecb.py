"""Режим AES-128 ECB с дополнением PKCS#7.

Блочный примитив AES предоставляет PyCryptodome. Разбиение на блоки и обработка
PKCS#7 реализованы здесь самостоятельно согласно требованиям первого спринта.
"""

from Crypto.Cipher import AES

from cryptocore.errors import InvalidCiphertextError, InvalidKeyError, InvalidPaddingError

BLOCK_SIZE = 16
KEY_SIZE = 16


def _validate_key(key: bytes) -> None:
    if not isinstance(key, bytes):
        raise InvalidKeyError("ключ AES-128 должен быть передан как байты")
    if len(key) != KEY_SIZE:
        raise InvalidKeyError("ключ AES-128 должен иметь длину ровно 16 байт")


def _pkcs7_pad(data: bytes) -> bytes:
    padding_length = BLOCK_SIZE - (len(data) % BLOCK_SIZE)
    return data + bytes([padding_length]) * padding_length


def _pkcs7_unpad(data: bytes) -> bytes:
    if not data or len(data) % BLOCK_SIZE != 0:
        raise InvalidPaddingError("расшифрованные данные имеют некорректное дополнение PKCS#7")

    padding_length = data[-1]
    if padding_length < 1 or padding_length > BLOCK_SIZE:
        raise InvalidPaddingError("расшифрованные данные имеют некорректное дополнение PKCS#7")

    expected_padding = bytes([padding_length]) * padding_length
    if data[-padding_length:] != expected_padding:
        raise InvalidPaddingError("расшифрованные данные имеют некорректное дополнение PKCS#7")
    return data[:-padding_length]


def encrypt_ecb(plaintext: bytes, key: bytes) -> bytes:
    """Зашифровать произвольные байты в AES-128 ECB с дополнением PKCS#7."""
    _validate_key(key)
    cipher = AES.new(key, AES.MODE_ECB)
    padded = _pkcs7_pad(plaintext)
    encrypted_blocks = (
        cipher.encrypt(padded[offset : offset + BLOCK_SIZE])
        for offset in range(0, len(padded), BLOCK_SIZE)
    )
    return b"".join(encrypted_blocks)


def decrypt_ecb(ciphertext: bytes, key: bytes) -> bytes:
    """Расшифровать AES-128 ECB, проверить и удалить дополнение PKCS#7."""
    _validate_key(key)
    if not ciphertext or len(ciphertext) % BLOCK_SIZE != 0:
        raise InvalidCiphertextError(
            "шифротекст AES-ECB не должен быть пустым, а его длина должна быть кратна 16 байтам"
        )

    cipher = AES.new(key, AES.MODE_ECB)
    decrypted_blocks = (
        cipher.decrypt(ciphertext[offset : offset + BLOCK_SIZE])
        for offset in range(0, len(ciphertext), BLOCK_SIZE)
    )
    return _pkcs7_unpad(b"".join(decrypted_blocks))
