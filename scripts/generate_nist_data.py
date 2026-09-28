"""Создать бинарный файл из CSPRNG CryptoCore для статистических тестов."""

import argparse
from pathlib import Path

from cryptocore.csprng import generate_random_bytes


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--size", type=int, default=10_000_000, help="размер файла в байтах")
    parser.add_argument("--output", type=Path, default=Path("nist_test_data.bin"))
    args = parser.parse_args()
    if args.size <= 0:
        parser.error("--size должен быть положительным")

    remaining = args.size
    with args.output.open("wb") as destination:
        while remaining:
            chunk = generate_random_bytes(min(1_048_576, remaining))
            destination.write(chunk)
            remaining -= len(chunk)
    print(f"Создан файл {args.output} размером {args.size} байт")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
