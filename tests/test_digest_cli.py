"""Интеграционные тесты подкоманды ``cryptocore dgst``."""

import contextlib
import hashlib
import io
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

from cryptocore.cli import build_digest_parser, main


def find_openssl():
    """Найти системный OpenSSL или версию из Git for Windows."""
    configured = os.environ.get("OPENSSL")
    if configured:
        return configured
    found = shutil.which("openssl")
    if found:
        return found
    bundled = Path("C:/Program Files/Git/usr/bin/openssl.exe")
    return str(bundled) if bundled.is_file() else None


class DigestCliTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.source = self.root / "данные.bin"
        self.output = self.root / "digest.txt"
        self.data = bytes(range(256)) * 17 + b"CryptoCore sprint 4"
        self.source.write_bytes(self.data)

    def test_stdout_format_for_both_algorithms(self):
        for algorithm, reference in (
            ("sha256", hashlib.sha256),
            ("sha3-256", hashlib.sha3_256),
        ):
            with self.subTest(algorithm=algorithm):
                stdout = io.StringIO()
                with contextlib.redirect_stdout(stdout):
                    status = main([
                        "dgst", "--algorithm", algorithm,
                        "--input", str(self.source),
                    ])
                self.assertEqual(status, 0)
                self.assertEqual(
                    stdout.getvalue(),
                    f"{reference(self.data).hexdigest()}  {self.source}\n",
                )

    def test_output_file_uses_same_format_and_suppresses_stdout(self):
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            status = main([
                "dgst", "--algorithm", "sha3-256", "--input", str(self.source),
                "--output", str(self.output),
            ])
        expected = f"{hashlib.sha3_256(self.data).hexdigest()}  {self.source}\n"
        self.assertEqual(status, 0)
        self.assertEqual(stdout.getvalue(), "")
        self.assertEqual(self.output.read_text(encoding="utf-8"), expected)

    def test_standard_input(self):
        class Input:
            def __init__(self, data):
                self.buffer = io.BytesIO(data)

        stdout = io.StringIO()
        original_stdin = sys.stdin
        try:
            sys.stdin = Input(self.data)
            with contextlib.redirect_stdout(stdout):
                status = main(["dgst", "--algorithm", "sha256", "--input", "-"])
        finally:
            sys.stdin = original_stdin
        self.assertEqual(status, 0)
        self.assertEqual(stdout.getvalue(), f"{hashlib.sha256(self.data).hexdigest()}  -\n")

    def test_encryption_arguments_are_rejected(self):
        for forbidden in ("--key", "--mode", "--encrypt", "--decrypt", "--iv"):
            arguments = ["--algorithm", "sha256", "--input", str(self.source), forbidden]
            if forbidden in ("--key", "--mode", "--iv"):
                arguments.append("value")
            with self.subTest(argument=forbidden):
                errors = io.StringIO()
                with contextlib.redirect_stderr(errors), self.assertRaises(SystemExit) as exit_error:
                    build_digest_parser().parse_args(arguments)
                self.assertEqual(exit_error.exception.code, 2)
                self.assertIn("нераспознанные аргументы", errors.getvalue())

    def test_invalid_algorithm_is_reported_in_russian(self):
        errors = io.StringIO()
        with contextlib.redirect_stderr(errors), self.assertRaises(SystemExit):
            main(["dgst", "--algorithm", "md5", "--input", str(self.source)])
        self.assertIn("недопустимое значение", errors.getvalue())
        self.assertNotIn("invalid choice", errors.getvalue())

    def test_help_is_in_russian(self):
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout), self.assertRaises(SystemExit) as exit_error:
            build_digest_parser().parse_args(["--help"])
        help_text = stdout.getvalue()
        self.assertEqual(exit_error.exception.code, 0)
        self.assertIn("использование:", help_text)
        self.assertIn("параметры:", help_text)
        self.assertIn("показать эту справку", help_text)
        self.assertNotIn("show this help", help_text)

    def test_missing_file_is_clear_and_output_is_not_created(self):
        errors = io.StringIO()
        with contextlib.redirect_stderr(errors):
            status = main([
                "dgst", "--algorithm", "sha256",
                "--input", str(self.root / "нет.bin"), "--output", str(self.output),
            ])
        self.assertEqual(status, 1)
        self.assertIn("входной файл не найден", errors.getvalue())
        self.assertFalse(self.output.exists())

    def test_module_entry_point(self):
        completed = subprocess.run(
            [
                sys.executable, "-m", "cryptocore", "dgst", "--algorithm", "sha256",
                "--input", str(self.source),
            ],
            check=True,
            capture_output=True,
            text=True,
            encoding="utf-8",
        )
        self.assertEqual(
            completed.stdout,
            f"{hashlib.sha256(self.data).hexdigest()}  {self.source}\n",
        )
        self.assertEqual(completed.stderr, "")

    def test_compatibility_with_openssl(self):
        openssl = find_openssl()
        if not openssl:
            self.skipTest("OpenSSL не найден: добавьте его в PATH или задайте OPENSSL")
        for algorithm, option in (("sha256", "-sha256"), ("sha3-256", "-sha3-256")):
            with self.subTest(algorithm=algorithm):
                expected = subprocess.run(
                    [openssl, "dgst", option, "-binary", str(self.source)],
                    check=True,
                    capture_output=True,
                ).stdout.hex()
                stdout = io.StringIO()
                with contextlib.redirect_stdout(stdout):
                    status = main([
                        "dgst", "--algorithm", algorithm, "--input", str(self.source)
                    ])
                self.assertEqual(status, 0)
                self.assertEqual(stdout.getvalue().split()[0], expected)


if __name__ == "__main__":
    unittest.main()
