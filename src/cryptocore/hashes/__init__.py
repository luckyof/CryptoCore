"""Публичный интерфейс собственных криптографических хеш-функций."""

from typing import Union

from .sha256 import SHA256
from .sha3_256 import SHA3_256


HashObject = Union[SHA256, SHA3_256]
ALGORITHMS = ("sha256", "sha3-256")


def create_hash(algorithm: str) -> HashObject:
    """Создать потоковый объект выбранного алгоритма."""
    if algorithm == "sha256":
        return SHA256()
    if algorithm == "sha3-256":
        return SHA3_256()
    raise ValueError(f"неподдерживаемый алгоритм хеширования: {algorithm}")


__all__ = ["ALGORITHMS", "SHA256", "SHA3_256", "create_hash"]
