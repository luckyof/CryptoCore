"""Измерение собственной PBKDF2 с независимой проверкой результата."""

import hashlib
import json
from pathlib import Path
import platform
import sys
from time import perf_counter

from cryptocore.kdf import pbkdf2_hmac_sha256
from cryptocore.cli import RussianArgumentParser, _derive_integer, _derive_length


def main() -> int:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
    parser = RussianArgumentParser(description="Измерить время PBKDF2-HMAC-SHA256 проекта")
    parser.add_argument("--iterations", type=_derive_integer, nargs="+", default=[10000, 100000, 1000000])
    parser.add_argument("--length", type=_derive_length, default=32)
    parser.add_argument("--report", type=Path)
    args = parser.parse_args()
    if any(value <= 0 for value in args.iterations) or args.length <= 0:
        parser.error("числа итераций и длина должны быть положительными")
    # Только публичные тестовые данные, не пароль пользователя.
    password, salt = b"benchmark-password", bytes(range(16))
    report = {"python": platform.python_version(), "platform": platform.platform(),
              "algorithm": "PBKDF2-HMAC-SHA256 (собственные SHA-256 и HMAC)",
              "length": args.length, "results": []}
    for iterations in args.iterations:
        print(f"Запуск: {iterations} итераций, {args.length} байт", flush=True)
        start = perf_counter()
        result = pbkdf2_hmac_sha256(password, salt, iterations, args.length)
        elapsed = perf_counter() - start
        # hashlib здесь только эталон, не реализация рабочего KDF.
        expected = hashlib.pbkdf2_hmac("sha256", password, salt, iterations, args.length)
        if result != expected:
            raise AssertionError("результат PBKDF2 не совпал с эталоном")
        report["results"].append({"iterations": iterations, "seconds": round(elapsed, 6),
                                  "matches_reference": True})
        print(f"Готово: {elapsed:.6f} с; совпадение с эталоном: да", flush=True)
        if args.report:
            args.report.parent.mkdir(parents=True, exist_ok=True)
            args.report.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
