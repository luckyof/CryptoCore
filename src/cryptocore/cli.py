"""Интерфейс командной строки CryptoCore."""

import argparse
import os
import re
import sys
from pathlib import Path
from typing import Optional, Sequence

from cryptocore.errors import CryptoCoreError, InvalidKeyError
from cryptocore.file_io import read_binary_file, write_binary_file
from cryptocore.modes.ecb import decrypt_ecb, encrypt_ecb
from cryptocore.modes.feedback import MODES


def _translate_parser_error(message: str) -> str:
    """Перевести стандартные сообщения argparse на русский язык."""
    patterns = (
        (
            r"^the following arguments are required: (.+)$",
            r"не указаны обязательные аргументы: \1",
        ),
        (
            r"^one of the arguments (.+) is required$",
            r"необходимо указать один из аргументов: \1",
        ),
        (
            r"^argument (.+?): not allowed with argument (.+)$",
            r"аргумент \1 нельзя использовать вместе с аргументом \2",
        ),
        (
            r"^argument (.+?): invalid choice: (.+?) \(choose from (.+)\)$",
            r"аргумент \1: недопустимое значение \2 (допустимые значения: \3)",
        ),
        (
            r"^unrecognized arguments: (.+)$",
            r"нераспознанные аргументы: \1",
        ),
    )
    for pattern, replacement in patterns:
        translated, count = re.subn(pattern, replacement, message)
        if count:
            return translated

    translated = message.replace("expected one argument", "ожидалось одно значение")
    return re.sub(r"^argument ", "аргумент ", translated)


class RussianArgumentParser(argparse.ArgumentParser):
    """Парсер аргументов с русскоязычным выводом ошибок."""

    def error(self, message: str) -> None:
        usage = self.format_usage().replace("usage:", "использование:", 1)
        self._print_message(usage, sys.stderr)
        self.exit(2, f"{self.prog}: ошибка: {_translate_parser_error(message)}\n")


def _configure_console_encoding() -> None:
    """Использовать UTF-8 для корректного вывода кириллицы в перенаправленные потоки."""
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is not None:
            reconfigure(encoding="utf-8")


def _hex_key(value: str) -> bytes:
    if len(value) != 32:
        raise argparse.ArgumentTypeError(
            "ключ AES-128 должен содержать ровно 32 шестнадцатеричных символа"
        )
    try:
        key = bytes.fromhex(value)
    except ValueError as error:
        raise argparse.ArgumentTypeError(
            "ключ AES-128 должен содержать только шестнадцатеричные символы"
        ) from error
    if len(key) != 16:
        raise argparse.ArgumentTypeError("ключ AES-128 должен декодироваться ровно в 16 байт")
    return key


def _hex_iv(value: str) -> bytes:
    if re.fullmatch(r"[0-9a-fA-F]{32}", value) is None:
        raise argparse.ArgumentTypeError("IV должен содержать ровно 32 шестнадцатеричных символа")
    return bytes.fromhex(value)


def build_parser() -> argparse.ArgumentParser:
    parser = RussianArgumentParser(
        prog="cryptocore",
        description="Шифрование и расшифрование файлов с помощью AES-128.",
        allow_abbrev=False,
    )
    parser.add_argument("--algorithm", required=True, choices=("aes",))
    parser.add_argument("--mode", required=True, choices=("ecb", *MODES))

    operation = parser.add_mutually_exclusive_group(required=True)
    operation.add_argument("--encrypt", action="store_true", help="зашифровать входной файл")
    operation.add_argument("--decrypt", action="store_true", help="расшифровать входной файл")

    parser.add_argument("--key", required=True, type=_hex_key, metavar="KEY")
    parser.add_argument("--iv", type=_hex_iv, metavar="IV",
                        help="IV в hex для расшифрования файла без заголовка")
    parser.add_argument("--input", required=True, type=Path, metavar="INPUT_FILE")
    parser.add_argument("--output", type=Path, metavar="OUTPUT_FILE")
    return parser


def _default_output(input_path: Path, encrypting: bool) -> Path:
    suffix = ".enc" if encrypting else ".dec"
    return input_path.with_name(input_path.name + suffix)


def run(args: argparse.Namespace) -> Path:
    input_path: Path = args.input
    output_path: Path = args.output or _default_output(input_path, args.encrypt)

    data = read_binary_file(input_path)
    if args.mode == "ecb":
        operation = encrypt_ecb if args.encrypt else decrypt_ecb
        result = operation(data, args.key)
    else:
        encrypt, decrypt = MODES[args.mode]
        if args.encrypt:
            try:
                iv = os.urandom(16)
            except OSError as error:
                raise CryptoCoreError("не удалось сгенерировать случайный IV") from error
            result = iv + encrypt(data, args.key, iv)
        else:
            iv = args.iv
            if iv is None:
                if len(data) < 16:
                    raise CryptoCoreError("файл слишком короткий: необходимы 16 байт IV")
                iv, data = data[:16], data[16:]
            result = decrypt(data, args.key, iv)
    write_binary_file(output_path, result)
    return output_path


def main(argv: Optional[Sequence[str]] = None) -> int:
    _configure_console_encoding()
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.iv is not None:
        if args.encrypt:
            parser.error("--iv разрешён только при расшифровании")
        if args.mode == "ecb":
            parser.error("режим ECB не использует IV")
    try:
        run(args)
    except InvalidKeyError as error:
        print(f"cryptocore: ошибка: {error}", file=sys.stderr)
        return 2
    except CryptoCoreError as error:
        print(f"cryptocore: ошибка: {error}", file=sys.stderr)
        return 1
    except OSError as error:
        target = error.filename or "файл"
        error_code = f", код {error.errno}" if error.errno is not None else ""
        print(
            f"cryptocore: ошибка: ошибка файловой системы при работе с '{target}'{error_code}",
            file=sys.stderr,
        )
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
