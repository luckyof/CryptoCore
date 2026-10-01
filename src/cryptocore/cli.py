"""Интерфейс командной строки CryptoCore."""

import argparse
import re
import sys
from pathlib import Path
from typing import Optional, Sequence

from cryptocore.errors import CryptoCoreError, InvalidKeyError
from cryptocore.csprng import generate_random_bytes, is_weak_aes_key
from cryptocore.file_io import read_binary_file, write_binary_file, write_text_file
from cryptocore.hashes import ALGORITHMS
from cryptocore.hashes.file_hash import hash_file, hash_stream
from cryptocore.key_files import load_key_file, save_key_file
from cryptocore.modes.gcm import encrypt_gcm, decrypt_gcm
from cryptocore.modes.authenticated import (
    encrypt_cbc_hmac, decrypt_cbc_hmac, encrypt_ctr_hmac, decrypt_ctr_hmac,
    DEFAULT_SEGMENT_SIZE, MAX_SEGMENT_SIZE,
)
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

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self._positionals.title = "позиционные аргументы"
        self._optionals.title = "параметры"
        for action in self._actions:
            if action.dest == "help":
                action.help = "показать эту справку и завершить работу"

    def format_help(self) -> str:
        """Полностью русифицировать стандартную справку argparse."""
        return super().format_help().replace("usage:", "использование:", 1)

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
    if re.fullmatch(r"(?:[0-9a-fA-F]{24}|[0-9a-fA-F]{32})", value) is None:
        raise argparse.ArgumentTypeError("IV должен содержать 32 hex-символа; nonce GCM — 24")
    return bytes.fromhex(value)


def _hex_aad(value: str) -> bytes:
    if re.fullmatch(r"(?:[0-9a-fA-F]{2})*", value) is None:
        raise argparse.ArgumentTypeError("AAD должен содержать чётное число hex-символов")
    return bytes.fromhex(value)


def _ctr_segment_size(value: str) -> int:
    if not value.isdecimal() or not 1 <= int(value) <= MAX_SEGMENT_SIZE:
        raise argparse.ArgumentTypeError(f"размер сегмента должен быть от 1 до {MAX_SEGMENT_SIZE} байт")
    return int(value)


def build_parser() -> argparse.ArgumentParser:
    parser = RussianArgumentParser(
        prog="cryptocore",
        description=(
            "Шифрование и расшифрование файлов с помощью AES-128. "
            "Для хеширования используйте: cryptocore dgst --help"
        ),
        allow_abbrev=False,
    )
    parser.add_argument("--algorithm", required=True, choices=("aes",))
    parser.add_argument("--mode", required=True, choices=("ecb", *MODES, "gcm", "cbc-hmac", "ctr-hmac"))

    operation = parser.add_mutually_exclusive_group(required=True)
    operation.add_argument("--encrypt", action="store_true", help="зашифровать входной файл")
    operation.add_argument("--decrypt", action="store_true", help="расшифровать входной файл")

    keys = parser.add_mutually_exclusive_group()
    keys.add_argument("--key", type=_hex_key, metavar="KEY",
                        help="ключ AES-128 в hex; при шифровании может генерироваться")
    keys.add_argument("--key-file", type=Path, help="читать hex-ключ из защищённого файла")
    parser.add_argument("--save-key", type=Path,
                        help="сохранить сгенерированный ключ в новый защищённый файл вместо stdout")
    parser.add_argument("--iv", "--nonce", dest="iv", type=_hex_iv, metavar="IV",
                        help="IV в hex для расшифрования файла без заголовка")
    parser.add_argument("--aad", type=_hex_aad, help="AAD в hex для gcm, cbc-hmac или ctr-hmac")
    parser.add_argument("--ctr-segment-size", type=_ctr_segment_size,
                        help="размер сегмента ctr-hmac для ротации nonce (по умолчанию 1 МиБ)")
    parser.add_argument("--input", required=True, type=Path, metavar="INPUT_FILE")
    parser.add_argument("--output", type=Path, metavar="OUTPUT_FILE")
    return parser


def build_digest_parser() -> argparse.ArgumentParser:
    """Создать отдельный парсер подкоманды ``dgst``."""
    parser = RussianArgumentParser(
        prog="cryptocore dgst",
        description="Потоковое вычисление криптографического хеша файла.",
        allow_abbrev=False,
    )
    parser.add_argument(
        "--algorithm",
        required=True,
        choices=ALGORITHMS,
        help="алгоритм хеширования",
    )
    parser.add_argument(
        "--input",
        required=True,
        type=Path,
        metavar="INPUT_FILE",
        help="входной файл или '-' для стандартного ввода",
    )
    parser.add_argument(
        "--output",
        type=Path,
        metavar="OUTPUT_FILE",
        help="записать результат в файл вместо stdout",
    )
    return parser


def _default_output(input_path: Path, encrypting: bool) -> Path:
    suffix = ".enc" if encrypting else ".dec"
    return input_path.with_name(input_path.name + suffix)


def run(args: argparse.Namespace) -> Path:
    input_path: Path = args.input
    output_path: Path = args.output or _default_output(input_path, args.encrypt)

    protected_paths = [input_path, output_path]
    if args.save_key and any(args.save_key.resolve() == path.resolve() for path in protected_paths):
        raise CryptoCoreError("ключевой файл не должен совпадать с входным файлом или шифротекстом")
    if args.key_file and (args.key_file.resolve() == output_path.resolve()
                         or (output_path.exists() and args.key_file.exists()
                             and args.key_file.samefile(output_path))):
        raise CryptoCoreError("выходной файл не должен перезаписывать ключевой файл")
    data = read_binary_file(input_path)
    key = load_key_file(args.key_file) if args.key_file else args.key
    if key is None:
        key = generate_random_bytes(16)
        if args.save_key is None:
            print(f"[ИНФО] Сгенерирован случайный ключ: {key.hex()}")
    elif is_weak_aes_key(key):
        print("cryptocore: предупреждение: указанный ключ выглядит слабым", file=sys.stderr)

    aad = args.aad or b""
    if args.mode == "gcm":
        if args.encrypt:
            nonce = generate_random_bytes(12)
            result = nonce + encrypt_gcm(data, key, nonce, aad)
        else:
            nonce = args.iv
            if nonce is None:
                nonce, data = data[:12], data[12:]
            result = decrypt_gcm(data, key, nonce, aad)
    elif args.mode == "cbc-hmac":
        result = (encrypt_cbc_hmac(data, key, generate_random_bytes(16), aad)
                  if args.encrypt else decrypt_cbc_hmac(data, key, aad))
    elif args.mode == "ctr-hmac":
        result = (encrypt_ctr_hmac(data, key, aad, args.ctr_segment_size or DEFAULT_SEGMENT_SIZE)
                  if args.encrypt else decrypt_ctr_hmac(data, key, aad))
    elif args.mode == "ecb":
        operation = encrypt_ecb if args.encrypt else decrypt_ecb
        result = operation(data, key)
    else:
        encrypt, decrypt = MODES[args.mode]
        if args.encrypt:
            iv = generate_random_bytes(16)
            result = iv + encrypt(data, key, iv)
        else:
            iv = args.iv
            if iv is None:
                if len(data) < 16:
                    raise CryptoCoreError("файл слишком короткий: необходимы 16 байт IV")
                iv, data = data[:16], data[16:]
            result = decrypt(data, key, iv)
    if args.save_key:
        save_key_file(args.save_key, key)
    write_binary_file(output_path, result)
    return output_path


def run_digest(args: argparse.Namespace) -> Optional[Path]:
    """Выполнить подкоманду хеширования и вывести строку формата *sum."""
    input_label = str(args.input)
    if input_label == "-":
        source = getattr(sys.stdin, "buffer", sys.stdin)
        digest = hash_stream(source, args.algorithm)
    else:
        digest = hash_file(args.input, args.algorithm)

    line = f"{digest}  {input_label}\n"
    if args.output is None:
        sys.stdout.write(line)
        return None
    write_text_file(args.output, line)
    return args.output


def main(argv: Optional[Sequence[str]] = None) -> int:
    _configure_console_encoding()
    arguments = list(sys.argv[1:] if argv is None else argv)
    if arguments[:1] == ["dgst"]:
        parser = build_digest_parser()
        args = parser.parse_args(arguments[1:])
        try:
            run_digest(args)
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

    parser = build_parser()
    args = parser.parse_args(arguments)
    if args.decrypt and args.key is None and args.key_file is None:
        parser.error("при расшифровании необходимо указать --key или --key-file")
    if args.save_key and (args.decrypt or args.key is not None or args.key_file is not None):
        parser.error("--save-key разрешён только при шифровании с генерацией нового ключа")
    if args.aad is not None and args.mode not in ("gcm", "cbc-hmac", "ctr-hmac"):
        parser.error("--aad разрешён только для gcm, cbc-hmac и ctr-hmac")
    if args.ctr_segment_size is not None and (args.mode != "ctr-hmac" or not args.encrypt):
        parser.error("--ctr-segment-size разрешён только для шифрования ctr-hmac")
    if args.iv is not None:
        if args.encrypt:
            parser.error("--iv разрешён только при расшифровании")
        if args.mode == "ecb":
            parser.error("режим ECB не использует IV")
        if args.mode in ("cbc-hmac", "ctr-hmac"):
            parser.error("аутентифицированный IV/nonce должен считываться из файла")
        expected = 12 if args.mode == "gcm" else 16
        if len(args.iv) != expected:
            parser.error(f"IV/nonce для {args.mode} должен содержать {expected} байт")
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
