"""Вспомогательные функции двоичного файлового ввода-вывода."""

from pathlib import Path

from cryptocore.errors import CryptoCoreError


def read_binary_file(path: Path) -> bytes:
    """Прочитать и вернуть всё содержимое файла *path*."""
    try:
        with path.open("rb") as source:
            return source.read()
    except FileNotFoundError as error:
        raise CryptoCoreError(f"входной файл не найден: '{path}'") from error
    except IsADirectoryError as error:
        raise CryptoCoreError(f"вместо входного файла указан каталог: '{path}'") from error
    except PermissionError as error:
        raise CryptoCoreError(f"нет прав на чтение входного файла: '{path}'") from error
    except OSError as error:
        raise CryptoCoreError(f"не удалось прочитать входной файл: '{path}'") from error


def write_binary_file(path: Path, data: bytes) -> None:
    """Записать *data* в *path* без преобразований кодировки текста."""
    try:
        with path.open("wb") as destination:
            destination.write(data)
    except FileNotFoundError as error:
        raise CryptoCoreError(f"каталог выходного файла не найден: '{path.parent}'") from error
    except IsADirectoryError as error:
        raise CryptoCoreError(f"вместо выходного файла указан каталог: '{path}'") from error
    except PermissionError as error:
        raise CryptoCoreError(f"нет прав на запись выходного файла: '{path}'") from error
    except OSError as error:
        raise CryptoCoreError(f"не удалось записать выходной файл: '{path}'") from error
