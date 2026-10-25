"""Чтение пароля из аргумента, файла или окружения; очистка изменяемых буферов."""

import os
from pathlib import Path

from cryptocore.errors import CryptoCoreError


def wipe(buffer: bytearray) -> None:
    """Перезаписать изменяемый буфер без выделения второго буфера той же длины."""
    zeros = bytes(8192)
    for offset in range(0, len(buffer), len(zeros)):
        amount = min(len(zeros), len(buffer) - offset)
        buffer[offset:offset + amount] = zeros[:amount]


def read_password(args) -> bytearray:
    """Файл читается буквально, включая переводы строк; строки кодируются UTF-8."""
    if args.password_file is not None:
        return _read_file(args.password_file)
    if args.password_env is not None:
        value = os.environ.get(args.password_env)
        if value is None:
            raise CryptoCoreError("переменная окружения с паролем не задана")
    else:
        value = args.password
        args.password = None
    try:
        return bytearray(value.encode("utf-8"))
    except UnicodeError as error:
        raise CryptoCoreError("не удалось представить пароль в UTF-8") from error
    finally:
        value = None


def _read_file(path: Path) -> bytearray:
    password = bytearray()
    buffer = bytearray(8192)
    try:
        with path.open("rb") as source:
            while True:
                size = source.readinto(buffer)
                if not size:
                    break
                password.extend(memoryview(buffer)[:size])
        return password
    except OSError as error:
        wipe(password)
        raise CryptoCoreError(f"не удалось прочитать файл пароля: '{path}'") from error
    except BaseException:
        wipe(password)
        raise
    finally:
        wipe(buffer)
