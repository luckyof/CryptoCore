"""Потоковое вычисление HMAC файлов и проверка полных тегов."""

from hmac import compare_digest
from pathlib import Path
import re
from typing import BinaryIO

from cryptocore.errors import CryptoCoreError
from cryptocore.hashes.file_hash import DEFAULT_CHUNK_SIZE
from .hmac import HMAC


def hmac_stream(stream: BinaryIO, key: bytes, chunk_size: int = DEFAULT_CHUNK_SIZE) -> str:
    """Читать фиксированные фрагменты, независимо от общего размера потока."""
    if not isinstance(chunk_size, int) or isinstance(chunk_size, bool) or chunk_size <= 0:
        raise ValueError("размер блока чтения должен быть положительным целым числом")
    mac = HMAC(key)
    while True:
        chunk = stream.read(chunk_size)
        if not chunk:
            break
        mac.update(chunk)
    return mac.hexdigest()


def hmac_file(path: Path, key: bytes) -> str:
    """Вычислить HMAC бинарного файла, не загружая файл целиком."""
    try:
        with path.open("rb") as source:
            return hmac_stream(source, key)
    except FileNotFoundError as error:
        raise CryptoCoreError(f"входной файл не найден: '{path}'") from error
    except IsADirectoryError as error:
        raise CryptoCoreError(f"вместо входного файла указан каталог: '{path}'") from error
    except PermissionError as error:
        raise CryptoCoreError(f"нет прав на чтение входного файла: '{path}'") from error
    except OSError as error:
        raise CryptoCoreError(f"не удалось прочитать входной файл: '{path}'") from error


def read_expected_hmac(path: Path) -> bytes:
    """Прочитать один полный hex-тег; необязательное имя файла игнорируется."""
    try:
        with path.open("r", encoding="utf-8-sig") as source:
            # Малый лимит исключает загрузку произвольного файла в память.
            text = source.read(65537)
    except (OSError, UnicodeError) as error:
        raise CryptoCoreError(f"не удалось прочитать файл ожидаемого HMAC: '{path}'") from error
    if len(text) > 65536:
        raise CryptoCoreError("файл ожидаемого HMAC превышает допустимый размер 65536 символов")
    lines = [line.strip() for line in text.splitlines() if line.strip()]
    if len(lines) != 1:
        raise CryptoCoreError("файл ожидаемого HMAC должен содержать одну непустую строку")
    token = lines[0].split(maxsplit=1)[0]
    if re.fullmatch(r"[0-9a-fA-F]{64}", token) is None:
        raise CryptoCoreError("ожидаемый HMAC должен содержать ровно 64 hex-символа")
    return bytes.fromhex(token)


def verify_hmac(actual: str, expected: bytes) -> bool:
    """Сравнить полные теги без раннего выхода по отличающемуся байту."""
    if re.fullmatch(r"[0-9a-fA-F]{64}", actual) is None or len(expected) != 32:
        raise ValueError("для проверки нужны полные 32-байтные теги HMAC-SHA256")
    return compare_digest(bytes.fromhex(actual), expected)
