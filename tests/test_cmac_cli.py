"""CLI-5 и TEST-8 спринта 5: генерация/проверка AES-CMAC и OpenSSL."""

import contextlib
import io
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from cryptocore.cli import main
from tests.test_cmac import KEY, MESSAGE, VECTORS
from tests.test_digest_cli import find_openssl


class CmacCliTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.source = self.root / "данные с пробелами.bin"
        self.output = self.root / "tag.txt"
        self.source.write_bytes(MESSAGE)

    def args(self):
        return ["dgst", "--algorithm", "aes", "--cmac", "--key", KEY.hex(), "--input", str(self.source)]

    def invoke(self, arguments):
        stdout, stderr = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            code = main(arguments)
        return code, stdout.getvalue(), stderr.getvalue()

    def test_all_known_vectors_through_stdout(self):
        for size, expected in VECTORS:
            with self.subTest(size=size):
                self.source.write_bytes(MESSAGE[:size])
                self.assertEqual(self.invoke(self.args()), (0, f"{expected} {self.source}\n", ""))

    def test_output_file_and_verify_roundtrip(self):
        self.assertEqual(self.invoke(self.args() + ["--output", str(self.output)]), (0, "", ""))
        self.assertEqual(self.output.read_text(encoding="utf-8"), f"{VECTORS[-1][1]} {self.source}\n")
        self.assertEqual(self.invoke(self.args() + ["--verify", str(self.output)]),
                         (0, "[OK] Проверка CMAC пройдена\n", ""))

    def test_wrong_key_changed_data_and_changed_tag_fail_without_success_output(self):
        self.assertEqual(self.invoke(self.args() + ["--output", str(self.output)])[0], 0)
        original_tag = self.output.read_bytes()
        original_data = self.source.read_bytes()
        arguments = self.args() + ["--verify", str(self.output)]
        wrong_key = list(arguments)
        wrong_key[wrong_key.index("--key") + 1] = (b"x" * 16).hex()
        wrong_key_result = self.invoke(wrong_key)
        self.source.write_bytes(bytes([original_data[0] ^ 1]) + original_data[1:])
        changed_data_result = self.invoke(arguments)
        self.source.write_bytes(original_data)
        self.output.write_bytes(b"0" + original_tag[1:])
        changed_tag_result = self.invoke(arguments)
        self.assertEqual(wrong_key_result, changed_data_result)
        self.assertEqual(wrong_key_result, changed_tag_result)
        self.assertEqual(wrong_key_result[:2], (1, ""))
        self.assertIn("проверка CMAC не пройдена", wrong_key_result[2])
        self.assertEqual(self.source.read_bytes(), original_data)

    def test_default_algorithm_and_standard_input(self):
        arguments = self.args()
        del arguments[1:3]
        self.assertEqual(self.invoke(arguments), self.invoke(self.args()))

        class Input:
            def __init__(self):
                self.buffer = io.BytesIO(MESSAGE)

        arguments[-1] = "-"
        original = sys.stdin
        try:
            sys.stdin = Input()
            self.assertEqual(self.invoke(arguments), (0, f"{VECTORS[-1][1]} -\n", ""))
            sys.stdin = Input()
            self.assertEqual(self.invoke(arguments + ["--output", str(self.output)]), (0, "", ""))
            sys.stdin = Input()
            self.assertEqual(self.invoke(arguments + ["--verify", str(self.output)]),
                             (0, "[OK] Проверка CMAC пройдена\n", ""))
        finally:
            sys.stdin = original

    def test_invalid_keys_algorithms_and_flag_combinations(self):
        base = ["dgst", "--cmac", "--input", str(self.source)]
        cases = [base, self.args() + ["--hmac"],
                 self.args() + ["--verify", str(self.output), "--output", str(self.output)],
                 ["dgst", "--algorithm", "aes", "--input", str(self.source)]]
        cases.extend(base + ["--key", key] for key in ("", "00", "ab" * 15, "ab" * 17, "ab" * 24, "ab" * 32, "zz", "0", "ab cd"))
        cases.extend(base + ["--key", KEY.hex(), "--algorithm", algorithm] for algorithm in ("sha256", "sha3-256"))
        for arguments in cases:
            with self.subTest(arguments=arguments):
                errors = io.StringIO()
                with contextlib.redirect_stderr(errors), self.assertRaises(SystemExit) as failure:
                    main(arguments)
                self.assertEqual(failure.exception.code, 2)
                self.assertIn("ошибка:", errors.getvalue())
                self.assertNotIn("Traceback", errors.getvalue())

    def test_invalid_expected_tags_and_missing_file(self):
        for tag in ("", "ab" * 15, "ab" * 32, "gg" * 16):
            self.output.write_text(tag, encoding="utf-8")
            code, stdout, stderr = self.invoke(self.args() + ["--verify", str(self.output)])
            self.assertEqual((code, stdout), (1, ""))
            self.assertIn("CMAC", stderr)
        self.output.unlink()
        self.assertEqual(self.invoke(self.args() + ["--verify", str(self.output)])[0], 1)

    def test_missing_input_preserves_existing_output(self):
        self.output.write_text("сохранить", encoding="utf-8")
        self.source.unlink()
        self.assertEqual(self.invoke(self.args() + ["--output", str(self.output)])[0], 1)
        self.assertEqual(self.output.read_text(encoding="utf-8"), "сохранить")

    def test_help_documents_cmac_and_module_exit_codes(self):
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout), self.assertRaises(SystemExit) as completed:
            main(["dgst", "--help"])
        self.assertEqual(completed.exception.code, 0)
        self.assertIn("--cmac", stdout.getvalue())
        self.assertIn("AES-128-CMAC", stdout.getvalue())
        self.invoke(self.args() + ["--output", str(self.output)])
        command = [sys.executable, "-m", "cryptocore", *self.args(), "--verify", str(self.output)]
        self.assertEqual(subprocess.run(command, capture_output=True, check=False).returncode, 0)
        self.source.write_bytes(b"changed")
        self.assertEqual(subprocess.run(command, capture_output=True, check=False).returncode, 1)

    def test_compatibility_with_openssl_for_all_vectors(self):
        openssl = find_openssl()
        if not openssl:
            self.skipTest("OpenSSL не найден")
        for size, expected in VECTORS:
            with self.subTest(size=size):
                self.source.write_bytes(MESSAGE[:size])
                result = subprocess.run(
                    [openssl, "dgst", "-mac", "CMAC", "-macopt", "cipher:AES-128-CBC",
                     "-macopt", f"hexkey:{KEY.hex()}", "-binary", str(self.source)],
                    capture_output=True, check=True,
                )
                self.assertEqual(result.stdout.hex(), expected)
                self.assertEqual(self.invoke(self.args())[1].split()[0], expected)


if __name__ == "__main__":
    unittest.main()
