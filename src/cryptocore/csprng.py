"""Единый криптографически стойкий источник случайных байтов."""

import os

from cryptocore.errors import CryptoCoreError


def generate_random_bytes(num_bytes: int) -> bytes:
    """Вернуть ``num_bytes`` случайных байтов из CSPRNG операционной системы."""
    if isinstance(num_bytes, bool) or not isinstance(num_bytes, int):
        raise TypeError("количество случайных байтов должно быть целым числом")
    if num_bytes < 0:
        raise ValueError("количество случайных байтов не может быть отрицательным")
    try:
        return os.urandom(num_bytes)
    except OSError as error:
        raise CryptoCoreError(
            f"не удалось получить {num_bytes} случайных байтов от операционной системы"
        ) from error


def is_weak_aes_key(key: bytes) -> bool:
    """Найти очевидно слабые учебные ключи: повтор или последовательность байтов."""
    if len(key) != 16:
        return False
    if len(set(key)) == 1:
        return True
    increasing = bytes((key[0] + offset) % 256 for offset in range(len(key)))
    decreasing = bytes((key[0] - offset) % 256 for offset in range(len(key)))
    return key == increasing or key == decreasing
