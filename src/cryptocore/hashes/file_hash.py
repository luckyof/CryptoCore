"""Потоковое вычисление хешей для файлов и других бинарных потоков."""

from pathlib import Path
from typing import BinaryIO

from cryptocore.errors import CryptoCoreError

from . import create_hash


DEFAULT_CHUNK_SIZE = 8192


def hash_stream(stream: BinaryIO, algorithm: str, chunk_size: int = DEFAULT_CHUNK_SIZE) -> str:
    """Вычислить хеш потока, удерживая в памяти не более одного блока чтения."""
    if not isinstance(chunk_size, int) or isinstance(chunk_size, bool) or chunk_size <= 0:
        raise ValueError("размер блока чтения должен быть положительным целым числом")
    hasher = create_hash(algorithm)
    while True:
        chunk = stream.read(chunk_size)
        if not chunk:
            break
        hasher.update(chunk)
    return hasher.hexdigest()


def hash_file(path: Path, algorithm: str) -> str:
    """Потоково вычислить хеш бинарного файла."""
    try:
        with path.open("rb") as source:
            return hash_stream(source, algorithm)
    except FileNotFoundError as error:
        raise CryptoCoreError(f"входной файл не найден: '{path}'") from error
    except IsADirectoryError as error:
        raise CryptoCoreError(f"вместо входного файла указан каталог: '{path}'") from error
    except PermissionError as error:
        raise CryptoCoreError(f"нет прав на чтение входного файла: '{path}'") from error
    except OSError as error:
        raise CryptoCoreError(f"не удалось прочитать входной файл: '{path}'") from error


__all__ = ["DEFAULT_CHUNK_SIZE", "hash_file", "hash_stream"]
