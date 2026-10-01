"""Чтение hex-ключей и сохранение с доступом только для владельца."""

import os
from pathlib import Path
import re
import stat
import subprocess

from .errors import CryptoCoreError
from .modes.ecb import _validate_key


def _restrict_windows_access(path: Path) -> None:
    """Убрать наследуемый ACL и разрешить доступ текущему пользователю."""
    identity = subprocess.run(
        ["whoami.exe", "/user", "/fo", "csv", "/nh"],
        check=True, capture_output=True,
    )
    match = re.search(rb"S-1-\d+(?:-\d+)+", identity.stdout)
    if match is None:
        raise CryptoCoreError("не удалось определить SID владельца ключевого файла")
    sid = match.group().decode("ascii")
    subprocess.run(
        ["icacls.exe", str(path), "/inheritance:r", "/grant:r", f"*{sid}:(F)"],
        check=True, capture_output=True,
    )


def save_key_file(path: Path, key: bytes) -> None:
    """Создать новый файл; не перезаписывать существующие файлы и ссылки."""
    _validate_key(key)
    descriptor = None
    created = False
    try:
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        created = True
        if os.name == "nt":
            # Права ограничиваются на пустом файле до записи секрета.
            _restrict_windows_access(path)
        else:
            os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "wb") as destination:
            descriptor = None
            destination.write(key.hex().encode("ascii") + b"\n")
    except (OSError, subprocess.SubprocessError, CryptoCoreError) as error:
        if descriptor is not None:
            os.close(descriptor)
        if created:
            path.unlink(missing_ok=True)
        raise CryptoCoreError(
            f"не удалось безопасно сохранить ключ: '{path}' (файл должен быть новым)"
        ) from error


def load_key_file(path: Path) -> bytes:
    """Прочитать 32 hex-символа; в POSIX отклонить открытые права и ссылки."""
    descriptor = None
    try:
        if path.is_symlink():
            raise CryptoCoreError("ключевой файл не должен быть символической ссылкой")
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0))
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode):
            raise CryptoCoreError("ключевой файл должен быть обычным файлом")
        if os.name != "nt" and info.st_mode & 0o077:
            raise CryptoCoreError("ключевой файл доступен другим пользователям: установите права 0600")
        with os.fdopen(descriptor, "rb") as source:
            descriptor = None
            data = source.read(128)
        if re.fullmatch(rb"[0-9a-fA-F]{32}(?:\r?\n)?", data) is None:
            raise CryptoCoreError("ключевой файл должен содержать ровно 32 hex-символа")
        return bytes.fromhex(data.decode("ascii").strip())
    except OSError as error:
        raise CryptoCoreError(f"не удалось прочитать ключевой файл: '{path}'") from error
    finally:
        if descriptor is not None:
            os.close(descriptor)
