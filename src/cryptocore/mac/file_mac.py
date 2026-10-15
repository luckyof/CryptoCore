"""Потоковое вычисление HMAC/CMAC файлов и проверка полных тегов."""

from hmac import compare_digest
from pathlib import Path
import re
from typing import BinaryIO

from cryptocore.errors import CryptoCoreError
from cryptocore.hashes.file_hash import DEFAULT_CHUNK_SIZE
from .hmac import HMAC
from .cmac import CMAC


def _mac_stream(stream: BinaryIO, key: bytes, factory, chunk_size: int) -> str:
    """Читать фиксированные фрагменты, независимо от общего размера потока."""
    if not isinstance(chunk_size, int) or isinstance(chunk_size, bool) or chunk_size <= 0:
        raise ValueError("размер блока чтения должен быть положительным целым числом")
    mac = factory(key)
    while True:
        chunk = stream.read(chunk_size)
        if not chunk:
            break
        mac.update(chunk)
    return mac.hexdigest()


def _mac_file(path: Path, key: bytes, calculator) -> str:
    try:
        with path.open("rb") as source:
            return calculator(source, key)
    except FileNotFoundError as error:
        raise CryptoCoreError(f"входной файл не найден: '{path}'") from error
    except IsADirectoryError as error:
        raise CryptoCoreError(f"вместо входного файла указан каталог: '{path}'") from error
    except PermissionError as error:
        raise CryptoCoreError(f"нет прав на чтение входного файла: '{path}'") from error
    except OSError as error:
        raise CryptoCoreError(f"не удалось прочитать входной файл: '{path}'") from error


def hmac_stream(stream: BinaryIO, key: bytes, chunk_size: int = DEFAULT_CHUNK_SIZE) -> str:
    """Вычислить HMAC-SHA256 бинарного потока без накопления сообщения."""
    return _mac_stream(stream, key, HMAC, chunk_size)


def cmac_stream(stream: BinaryIO, key: bytes, chunk_size: int = DEFAULT_CHUNK_SIZE) -> str:
    """Вычислить AES-128-CMAC бинарного потока без накопления сообщения."""
    return _mac_stream(stream, key, CMAC, chunk_size)


def hmac_file(path: Path, key: bytes) -> str:
    """Вычислить HMAC бинарного файла, не загружая файл целиком."""
    return _mac_file(path, key, hmac_stream)


def cmac_file(path: Path, key: bytes) -> str:
    """Вычислить CMAC бинарного файла, не загружая файл целиком."""
    return _mac_file(path, key, cmac_stream)


def _read_expected_mac(path: Path, hex_size: int, label: str) -> bytes:
    """Прочитать один полный hex-тег; необязательное имя файла игнорируется."""
    try:
        with path.open("r", encoding="utf-8-sig") as source:
            # Малый лимит исключает загрузку произвольного файла в память.
            text = source.read(65537)
    except (OSError, UnicodeError) as error:
        raise CryptoCoreError(f"не удалось прочитать файл ожидаемого {label}: '{path}'") from error
    if len(text) > 65536:
        raise CryptoCoreError(f"файл ожидаемого {label} превышает допустимый размер 65536 символов")
    lines = [line.strip() for line in text.splitlines() if line.strip()]
    if len(lines) != 1:
        raise CryptoCoreError(f"файл ожидаемого {label} должен содержать одну непустую строку")
    token = lines[0].split(maxsplit=1)[0]
    if re.fullmatch(rf"[0-9a-fA-F]{{{hex_size}}}", token) is None:
        raise CryptoCoreError(f"ожидаемый {label} должен содержать ровно {hex_size} hex-символа")
    return bytes.fromhex(token)


def _verify_mac(actual: str, expected: bytes, digest_size: int, label: str) -> bool:
    """Сравнить полные теги без раннего выхода по отличающемуся байту."""
    if re.fullmatch(rf"[0-9a-fA-F]{{{digest_size * 2}}}", actual) is None or len(expected) != digest_size:
        raise ValueError(f"для проверки нужны полные {digest_size}-байтные теги {label}")
    return compare_digest(bytes.fromhex(actual), expected)


def read_expected_hmac(path: Path) -> bytes:
    """Прочитать полный 256-битный HMAC и необязательное имя файла."""
    return _read_expected_mac(path, 64, "HMAC")


def read_expected_cmac(path: Path) -> bytes:
    """Прочитать полный 128-битный CMAC и необязательное имя файла."""
    return _read_expected_mac(path, 32, "CMAC")


def verify_hmac(actual: str, expected: bytes) -> bool:
    """Сравнить полные теги HMAC-SHA256 через compare_digest."""
    return _verify_mac(actual, expected, 32, "HMAC-SHA256")


def verify_cmac(actual: str, expected: bytes) -> bool:
    """Сравнить полные теги AES-CMAC через compare_digest."""
    return _verify_mac(actual, expected, 16, "AES-CMAC")
