"""Запуск ``python -m cryptocore`` как обычной консольной команды."""

from .cli import main


if __name__ == "__main__":
    raise SystemExit(main())
