"""Собственная PBKDF2-HMAC-SHA256 по RFC 2898 / RFC 8018."""

from cryptocore.mac import HMAC


MAX_LENGTH = ((1 << 32) - 1) * 32


def validate_length(length: int) -> None:
    if not isinstance(length, int) or isinstance(length, bool) or not 1 <= length <= MAX_LENGTH:
        raise ValueError(f"длина ключа должна быть целым числом от 1 до {MAX_LENGTH} байт")


def as_bytes(value, name: str) -> bytes:
    if not isinstance(value, (bytes, bytearray, memoryview)):
        raise TypeError(f"{name} должен быть байтовой последовательностью")
    return bytes(value)


def pbkdf2_hmac_sha256(password, salt, iterations: int = 100000, dklen: int = 32) -> bytes:
    """Получить ровно dklen байт, используя собственный HMAC из спринта 5."""
    if not isinstance(iterations, int) or isinstance(iterations, bool) or iterations < 1:
        raise ValueError("число итераций должно быть положительным целым числом")
    validate_length(dklen)
    password = password.encode("utf-8") if isinstance(password, str) else as_bytes(password, "пароль")
    salt = as_bytes(salt, "salt")
    mac = HMAC(password)
    password = None  # Снять локальную ссылку; полное стирание объектов Python не гарантируется.
    prf = mac.digest_message
    result = bytearray()
    for index in range(1, (dklen + 31) // 32 + 1):
        previous = prf(salt + index.to_bytes(4, "big"))
        accumulated = int.from_bytes(previous, "big")
        for _ in range(1, iterations):
            previous = prf(previous)
            accumulated ^= int.from_bytes(previous, "big")
        result.extend(accumulated.to_bytes(32, "big"))
    return bytes(result[:dklen])
