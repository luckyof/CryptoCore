"""Потоковый GCM: проверка тега до AES-расшифрования и атомарная публикация."""

import os
from pathlib import Path
import tempfile
from typing import BinaryIO, Callable, Optional

from cryptocore.csprng import generate_random_bytes
from cryptocore.errors import AuthenticationError, CryptoCoreError
from cryptocore.modes.gcm import AADSource, AUTH_ERROR, GCMAuthenticator, GCTR, feed_aad


CHUNK_SIZE = 8192


def _chunk_size(size: int) -> None:
    if not isinstance(size, int) or isinstance(size, bool) or size <= 0:
        raise CryptoCoreError("размер фрагмента GCM должен быть положительным целым числом")


def _read_exact(source: BinaryIO, size: int) -> bytes:
    result = bytearray()
    while len(result) < size:
        chunk = source.read(size - len(result))
        if not chunk:
            raise AuthenticationError(AUTH_ERROR)
        result.extend(chunk)
    return bytes(result)


def encrypt_gcm_stream(source: BinaryIO, destination: BinaryIO, key: bytes, nonce: bytes,
                       aad: AADSource = b"", chunk_size: int = CHUNK_SIZE) -> None:
    """Записать 12-байтный nonce, потоковый шифротекст и полный 16-байтный тег."""
    _chunk_size(chunk_size)
    if not isinstance(nonce, bytes) or len(nonce) != 12:
        raise CryptoCoreError("файловый формат GCM требует nonce длиной ровно 12 байт")
    auth = GCMAuthenticator(key, nonce)
    feed_aad(auth, aad)
    counter = GCTR(auth.cipher, auth.initial)
    destination.write(nonce)
    while True:
        chunk = source.read(chunk_size)
        if not chunk:
            break
        ciphertext = counter.transform(chunk)
        auth.update_ciphertext(ciphertext)
        destination.write(ciphertext)
    destination.write(auth.digest())


def decrypt_gcm_stream(source: BinaryIO, destination: BinaryIO, key: bytes,
                       nonce: Optional[bytes] = None, aad: AADSource = b"",
                       chunk_size: int = CHUNK_SIZE) -> None:
    """Сохранить только шифротекст во временный снимок; расшифровать после verify."""
    _chunk_size(chunk_size)
    nonce = _read_exact(source, 12) if nonce is None else nonce
    if not isinstance(nonce, bytes) or len(nonce) != 12:
        raise CryptoCoreError("файловый формат GCM требует nonce длиной ровно 12 байт")
    auth = GCMAuthenticator(key, nonce)
    feed_aad(auth, aad)
    # Снимок исключает изменение входа между проверкой тега и расшифрованием.
    # До проверки здесь и в destination нет ни одного байта открытого текста.
    with tempfile.TemporaryFile(mode="w+b") as snapshot:
        tail = b""
        while True:
            chunk = source.read(chunk_size)
            if not chunk:
                break
            combined = tail + chunk
            if len(combined) > 16:
                ciphertext, tail = combined[:-16], combined[-16:]
                auth.update_ciphertext(ciphertext)
                snapshot.write(ciphertext)
            else:
                tail = combined
        auth.verify(tail)
        snapshot.seek(0)
        counter = GCTR(auth.cipher, auth.initial)
        while True:
            chunk = snapshot.read(chunk_size)
            if not chunk:
                break
            destination.write(counter.transform(chunk))


def process_gcm_file(input_path: Path, output_path: Path, key: bytes, encrypting: bool,
                     aad: AADSource = b"", nonce: Optional[bytes] = None,
                     before_commit: Optional[Callable[[], None]] = None) -> None:
    """Опубликовать результат только после успеха; ошибки сохраняют старый файл."""
    staged_path = None
    try:
        with input_path.open("rb") as source:
            descriptor, name = tempfile.mkstemp(prefix=".cryptocore-", suffix=".tmp", dir=output_path.parent)
            staged_path = Path(name)
            with os.fdopen(descriptor, "w+b") as destination:
                if encrypting:
                    nonce = generate_random_bytes(12) if nonce is None else nonce
                    encrypt_gcm_stream(source, destination, key, nonce, aad)
                else:
                    decrypt_gcm_stream(source, destination, key, nonce, aad)
                destination.flush()
                os.fsync(destination.fileno())
        if before_commit is not None:
            before_commit()
        os.replace(staged_path, output_path)
        staged_path = None
    finally:
        if staged_path is not None:
            staged_path.unlink(missing_ok=True)
