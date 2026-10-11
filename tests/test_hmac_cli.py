"""Интеграционные тесты генерации и проверки HMAC в CLI."""

import contextlib
import hashlib
import hmac
import io
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from cryptocore.cli import main
from tests.test_digest_cli import find_openssl


class HmacCliTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.source = self.root / "данные с пробелами.bin"
        self.output = self.root / "hmac.txt"
        self.data = bytes(range(256)) * 5 + b"CryptoCore sprint 5"
        self.source.write_bytes(self.data)
        self.key = b"\x0b" * 20

    def arguments(self, key=None):
        return ["dgst", "--algorithm", "sha256", "--hmac", "--key",
                self.key.hex() if key is None else key,
                "--input", str(self.source)]

    def invoke(self, arguments):
        stdout, stderr = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            code = main(arguments)
        return code, stdout.getvalue(), stderr.getvalue()

    def generate(self):
        code, stdout, stderr = self.invoke(self.arguments() + ["--output", str(self.output)])
        self.assertEqual((code, stdout, stderr), (0, "", ""))

    def test_stdout_format_and_arbitrary_key_lengths(self):
        for size in (0, 1, 16, 64, 100):
            with self.subTest(key_size=size):
                key = bytes(range(size))
                code, stdout, stderr = self.invoke(self.arguments(key.hex()))
                self.assertEqual(code, 0)
                self.assertEqual(stderr, "")
                self.assertEqual(stdout, f"{hmac.new(key, self.data, hashlib.sha256).hexdigest()} {self.source}\n")

    def test_output_file_and_verify_roundtrip(self):
        self.generate()
        expected = hmac.new(self.key, self.data, hashlib.sha256).hexdigest()
        self.assertEqual(self.output.read_text(encoding="utf-8"), f"{expected} {self.source}\n")
        code, stdout, stderr = self.invoke(self.arguments() + ["--verify", str(self.output)])
        self.assertEqual(code, 0)
        self.assertIn("Проверка HMAC пройдена", stdout)
        self.assertEqual(stderr, "")

    def test_one_changed_byte_and_wrong_key_fail_with_same_message(self):
        self.generate()
        arguments = self.arguments() + ["--verify", str(self.output)]
        changed = bytes([self.data[0] ^ 1]) + self.data[1:]
        self.source.write_bytes(changed)
        changed_result = self.invoke(arguments)
        self.source.write_bytes(self.data)
        wrong_key_result = self.invoke(self.arguments("ff" * 20) + ["--verify", str(self.output)])
        self.assertEqual(changed_result, wrong_key_result)
        self.assertEqual(changed_result[0], 1)
        self.assertEqual(changed_result[1], "")
        self.assertIn("проверка HMAC не пройдена", changed_result[2])

    def test_empty_input(self):
        self.source.write_bytes(b"")
        code, stdout, stderr = self.invoke(self.arguments())
        self.assertEqual((code, stderr), (0, ""))
        self.assertEqual(stdout.split()[0], hmac.new(self.key, b"", hashlib.sha256).hexdigest())

    def test_standard_input_generation_and_verification(self):
        class Input:
            buffer = io.BytesIO(self.data)

        arguments = self.arguments()
        arguments[-1] = "-"
        original = sys.stdin
        try:
            sys.stdin = Input()
            code, stdout, stderr = self.invoke(arguments)
            self.assertEqual((code, stderr), (0, ""))
            self.assertEqual(stdout, f"{hmac.new(self.key, self.data, hashlib.sha256).hexdigest()} -\n")
            self.output.write_text(stdout, encoding="utf-8")
            sys.stdin = Input()
            sys.stdin.buffer = io.BytesIO(self.data)
            code, stdout, stderr = self.invoke(arguments + ["--verify", str(self.output)])
            self.assertEqual((code, stderr), (0, ""))
            self.assertIn("Проверка HMAC пройдена", stdout)
        finally:
            sys.stdin = original

    def test_default_algorithm_for_hmac(self):
        arguments = self.arguments()
        del arguments[1:3]
        self.assertEqual(self.invoke(arguments), self.invoke(self.arguments()))

    def test_invalid_argument_combinations_are_in_russian(self):
        base = ["dgst", "--algorithm", "sha256", "--input", str(self.source)]
        cases = (
            (base + ["--hmac"], "необходимо указать --key"),
            (base + ["--key", "ab"], "только вместе с --hmac"),
            (base + ["--verify", str(self.output)], "только вместе с --hmac"),
            (["dgst", "--input", str(self.source)], "--algorithm"),
            (self.arguments() + ["--verify", str(self.output), "--output", str(self.output)], "нельзя использовать"),
            (["dgst", "--algorithm", "sha3-256", "--hmac", "--key", "ab", "--input", str(self.source)], "только алгоритм sha256"),
        )
        for arguments, message in cases:
            with self.subTest(arguments=arguments):
                errors = io.StringIO()
                with contextlib.redirect_stderr(errors), self.assertRaises(SystemExit) as failure:
                    main(arguments)
                self.assertEqual(failure.exception.code, 2)
                self.assertIn(message, errors.getvalue())

    def test_malformed_keys_are_rejected_without_exposing_the_key(self):
        for key in ("0", "abc", "zz", "00 11", "\t00", "0x11", "секрет"):
            with self.subTest(key=key):
                errors = io.StringIO()
                with contextlib.redirect_stderr(errors), self.assertRaises(SystemExit) as failure:
                    main(self.arguments(key))
                self.assertEqual(failure.exception.code, 2)
                self.assertIn("чётное число hex-символов", errors.getvalue())
                self.assertNotIn("Traceback", errors.getvalue())

    def test_missing_input_preserves_existing_output(self):
        self.output.write_text("сохранить", encoding="utf-8")
        self.source.unlink()
        code, stdout, stderr = self.invoke(self.arguments() + ["--output", str(self.output)])
        self.assertEqual((code, stdout), (1, ""))
        self.assertIn("входной файл не найден", stderr)
        self.assertEqual(self.output.read_text(encoding="utf-8"), "сохранить")

    def test_invalid_expected_tag_reports_error_without_traceback(self):
        for text in ("", "ab" * 16, "gg" * 32, "ab" * 32 + "\n" + "ab" * 32):
            self.output.write_text(text, encoding="utf-8")
            code, stdout, stderr = self.invoke(self.arguments() + ["--verify", str(self.output)])
            self.assertEqual((code, stdout), (1, ""))
            self.assertIn("ошибка:", stderr)
            self.assertNotIn("Traceback", stderr)
        self.output.unlink()
        self.assertEqual(self.invoke(self.arguments() + ["--verify", str(self.output)])[0], 1)

    def test_module_entry_point_exit_codes(self):
        self.generate()
        command = [sys.executable, "-m", "cryptocore", *self.arguments(), "--verify", str(self.output)]
        result = subprocess.run(command, capture_output=True, text=True, encoding="utf-8", check=False)
        self.assertEqual(result.returncode, 0)
        self.assertIn("Проверка HMAC пройдена", result.stdout)
        self.source.write_bytes(self.data + b"x")
        result = subprocess.run(command, capture_output=True, text=True, encoding="utf-8", check=False)
        self.assertEqual(result.returncode, 1)
        self.assertIn("проверка HMAC не пройдена", result.stderr)

    def test_hmac_matches_openssl(self):
        openssl = find_openssl()
        if openssl is None:
            self.skipTest("OpenSSL не найден")
        result = subprocess.run(
            [openssl, "dgst", "-sha256", "-mac", "HMAC", "-macopt", f"hexkey:{self.key.hex()}",
             "-binary", str(self.source)], check=True, capture_output=True,
        )
        self.assertEqual(self.invoke(self.arguments())[1].split()[0], result.stdout.hex())


if __name__ == "__main__":
    unittest.main()
