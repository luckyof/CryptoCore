"""Запустить переносимую реализацию батареи NIST SP 800-22 Rev. 1a."""

import argparse
import math
from pathlib import Path

import numpy
from nistrng import (
    SP800_22R1A_BATTERY,
    check_eligibility_all_battery,
    run_by_name_battery,
)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input", type=Path, help="бинарный файл со случайными данными")
    parser.add_argument("--report", type=Path, default=Path("nist_results.txt"))
    args = parser.parse_args()

    data = numpy.fromfile(args.input, dtype=numpy.uint8)
    if data.size == 0:
        parser.error("входной файл пуст")
    # nistrng заменяет нули на -1 и накапливает суммы по всей последовательности.
    # Знаковый int64 предотвращает и ошибку uint8, и переполнение int8.
    bits = numpy.unpackbits(data).astype(numpy.int64)
    eligible = check_eligibility_all_battery(bits, SP800_22R1A_BATTERY)
    missing = sorted(set(SP800_22R1A_BATTERY) - set(eligible))
    # Некоторые тесты nistrng изменяют переданный массив через представления.
    # Отдельная копия сохраняет исходную последовательность для каждого теста.
    results = [
        run_by_name_battery(name, bits.copy(), eligible, False)
        for name in eligible
    ]

    lines = [
        "NIST SP 800-22 Rev. 1a (реализация nistrng 1.2.3)",
        f"Файл: {args.input}",
        f"Битов: {bits.size}",
        f"Запущено тестов: {len(results)} из {len(SP800_22R1A_BATTERY)}",
    ]
    passed = 0
    for result, elapsed_ms in results:
        status = "ПРОЙДЕН" if result.passed else "НЕ ПРОЙДЕН"
        passed += int(result.passed)
        lines.append(
            f"{status}: {result.name}; p-value={result.score}; время={elapsed_ms} мс"
        )
    lines.append(f"Итог: пройдено {passed} из {len(results)}")
    if missing:
        lines.append("Не подходят по длине данных: " + ", ".join(missing))
    report = "\n".join(lines) + "\n"
    args.report.write_text(report, encoding="utf-8")
    print(report, end="")
    required_passes = math.ceil(len(results) * 0.8)
    return 0 if not missing and passed >= required_passes else 1


if __name__ == "__main__":
    raise SystemExit(main())
