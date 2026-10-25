"""CLI и безопасный файловый вывод PBKDF2 седьмого спринта."""

import contextlib
import hashlib
import io
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from cryptocore.cli import build_derive_parser, main, run_derive
from cryptocore.errors import CryptoCoreError
from cryptocore.kdf.passwords import read_password, wipe
from cryptocore.key_files import load_key_file
from tests.test_digest_cli import find_openssl


SALT = bytes(range(16))


class DeriveCliTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.password_file = self.root / "password.bin"
        self.output = self.root / "derived.key"

    def args(self, *extra):
        return ["derive", "--password", "пароль !$ ' 😀", "--salt", SALT.hex(),
                "--iterations", "2", "--length", "32", *extra]

    def invoke(self, args):
        stdout, stderr = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            code = main(args)
        return code, stdout.getvalue(), stderr.getvalue()

    def test_stdout_exact_format_and_unicode_password(self):
        password = "пароль !$ ' 😀"
        key = hashlib.pbkdf2_hmac("sha256", password.encode(), SALT, 2, 32)
        code, stdout, stderr = self.invoke(self.args())
        self.assertEqual((code, stdout), (0, f"{key.hex()}  {SALT.hex()}\n"))
        self.assertIn("предупреждение", stderr)
        self.assertNotIn(password, stderr)

    def test_defaults_without_spending_100000_iterations_each_time(self):
        args = build_derive_parser().parse_args(["--password", "p"])
        self.assertEqual((args.algorithm, args.iterations, args.length, args.salt), ("pbkdf2", 100000, 32, None))
        with patch("cryptocore.cli.pbkdf2_hmac_sha256", return_value=b"k" * 32) as derive:
            with patch("cryptocore.cli.generate_random_bytes", return_value=SALT):
                code, stdout, stderr = self.invoke(["derive", "--password", "p"])
        self.assertEqual((code, stderr), (0, ""))
        self.assertEqual(stdout, f"{(b'k' * 32).hex()}  {SALT.hex()}\n")
        self.assertEqual(derive.call_args.args[1:], (SALT, 100000, 32))

    def test_generated_salts_unique_in_1000_real_cli_derivations(self):
        salts, keys = set(), set()
        for _ in range(1000):
            code, stdout, _ = self.invoke(["derive", "--password", "p", "--iterations", "1", "--length", "16"])
            self.assertEqual(code, 0)
            key, salt = stdout.strip().split("  ")
            self.assertEqual((len(key), len(salt)), (32, 32))
            self.assertEqual(bytes.fromhex(key), hashlib.pbkdf2_hmac("sha256", b"p", bytes.fromhex(salt), 1, 16))
            salts.add(salt)
            keys.add(key)
        self.assertEqual(len(salts), 1000)
        self.assertEqual(len(keys), 1000)

    def test_empty_password_salt_and_varied_lengths(self):
        for length in (1, 16, 32, 33, 100):
            code, stdout, stderr = self.invoke(["derive", "--password", "", "--salt", "", "--iterations", "1", "--length", str(length)])
            self.assertEqual(code, 0)
            expected = hashlib.pbkdf2_hmac("sha256", b"", b"", 1, length)
            self.assertEqual(stdout, f"{expected.hex()}  \n")

    def test_password_file_exact_bytes_including_newline_and_null(self):
        password = b"\xff\x00password\r\n"
        self.password_file.write_bytes(password)
        code, stdout, stderr = self.invoke(["derive", "--password-file", str(self.password_file), "--salt", SALT.hex(), "--iterations", "2"])
        self.assertEqual(code, 0)
        self.assertEqual(stdout.split()[0], hashlib.pbkdf2_hmac("sha256", password, SALT, 2, 32).hex())
        self.assertEqual(self.password_file.read_bytes(), password)
        self.assertNotIn("password", stderr)

    def test_environment_password_and_no_environment_mutation(self):
        with patch.dict(os.environ, {"CRYPTOCORE_TEST_PASSWORD": "пароль\n"}):
            arguments = ["derive", "--password-env", "CRYPTOCORE_TEST_PASSWORD", "--salt", SALT.hex(), "--iterations", "2"]
            code, stdout, stderr = self.invoke(arguments)
            self.assertEqual(code, 0)
            self.assertEqual(stdout.split()[0], hashlib.pbkdf2_hmac("sha256", "пароль\n".encode(), SALT, 2, 32).hex())
            self.assertEqual(os.environ["CRYPTOCORE_TEST_PASSWORD"], "пароль\n")
            self.assertNotIn("пароль\n", stderr)

    def test_raw_binary_output_without_salt_and_posix_mode(self):
        code, stdout, stderr = self.invoke(self.args("--length", "16", "--output", str(self.output)))
        self.assertEqual(code, 0)
        key_hex, salt_hex = stdout.strip().split("  ")
        self.assertEqual(self.output.read_bytes(), bytes.fromhex(key_hex))
        self.assertEqual(len(self.output.read_bytes()), 16)
        self.assertEqual(salt_hex, SALT.hex())
        if os.name == "posix":
            self.assertEqual(stat.S_IMODE(self.output.stat().st_mode), 0o600)
        with self.assertRaises(CryptoCoreError):
            load_key_file(self.output)  # Старый hex-формат ключей AES не переопределяется.

    def test_existing_output_and_password_source_never_overwritten(self):
        self.output.write_bytes(b"keep")
        with patch("cryptocore.cli.pbkdf2_hmac_sha256") as derive:
            code, stdout, _ = self.invoke(self.args("--output", str(self.output)))
            derive.assert_not_called()
        self.assertEqual((code, stdout), (1, ""))
        self.assertEqual(self.output.read_bytes(), b"keep")
        self.password_file.write_bytes(b"secret")
        code, stdout, _ = self.invoke(["derive", "--password-file", str(self.password_file), "--iterations", "1", "--output", str(self.password_file)])
        self.assertEqual((code, stdout), (1, ""))
        self.assertEqual(self.password_file.read_bytes(), b"secret")

    def test_errors_do_not_create_output_or_expose_password(self):
        arguments = ["derive", "--password-file", str(self.password_file), "--output", str(self.output), "--iterations", "1"]
        self.assertEqual(self.invoke(arguments)[0], 1)
        with patch.dict(os.environ, {}, clear=True):
            self.assertEqual(self.invoke(["derive", "--password-env", "MISSING_SECRET"])[0], 1)
        with patch("cryptocore.cli.generate_random_bytes", side_effect=CryptoCoreError("источник случайности недоступен")):
            self.assertEqual(self.invoke(["derive", "--password", "do-not-leak", "--output", str(self.output)])[0], 1)
        with patch("cryptocore.cli.save_binary_key_file", side_effect=CryptoCoreError("не удалось сохранить ключ")):
            code, stdout, stderr = self.invoke(self.args("--output", str(self.output)))
            self.assertEqual((code, stdout), (1, ""))
        self.assertFalse(self.output.exists())

    def test_password_buffer_is_wiped_on_success_and_failure(self):
        for fails in (False, True):
            password = bytearray(b"secret")
            args = build_derive_parser().parse_args(["--password", "secret", "--salt", SALT.hex(), "--iterations", "1"])
            with patch("cryptocore.cli.read_password", return_value=password):
                with patch("cryptocore.cli.pbkdf2_hmac_sha256", side_effect=CryptoCoreError("отказ") if fails else None, return_value=b"k" * 32):
                    with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                        if fails:
                            with self.assertRaises(CryptoCoreError):
                                run_derive(args)
                        else:
                            run_derive(args)
            self.assertEqual(password, bytes(6))
            self.assertIsNone(args.password)
        original = bytearray(b"secret" * 10000)
        wipe(original)
        self.assertEqual(original, bytes(len(original)))

    def test_password_argument_reference_released_after_read(self):
        args = build_derive_parser().parse_args(["--password", "secret"])
        password = read_password(args)
        self.assertIsNone(args.password)
        self.assertEqual(password, b"secret")
        wipe(password)

    def test_invalid_arguments_are_in_russian(self):
        cases = (["derive"], ["derive", "--password", "p", "--password-env", "NAME"],
                 ["derive", "--password", "p", "--algorithm", "hkdf"],
                 ["derive", "--password-env", "a=b"])
        cases = list(cases)
        for flag, values in (("--iterations", ("0", "-1", "1.5", "wrong", "9" * 5000)),
                             ("--length", ("0", "-1", "1.5", str(((1 << 32) - 1) * 32 + 1))),
                             ("--salt", ("0", "gg", "0x12", "aa bb", "fixedappsalt"))):
            cases.extend(["derive", "--password", "secret", flag, value] for value in values)
        for arguments in cases:
            errors = io.StringIO()
            with contextlib.redirect_stderr(errors), self.assertRaises(SystemExit) as failure:
                main(arguments)
            self.assertEqual(failure.exception.code, 2)
            self.assertIn("ошибка:", errors.getvalue())
            self.assertNotIn("secret", errors.getvalue())
            self.assertNotIn("Traceback", errors.getvalue())

    def test_help_and_module_entry_point(self):
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout), self.assertRaises(SystemExit) as completed:
            main(["derive", "--help"])
        self.assertEqual(completed.exception.code, 0)
        self.assertIn("--password-file", stdout.getvalue())
        self.assertIn("--password-env", stdout.getvalue())
        result = subprocess.run([sys.executable, "-m", "cryptocore", *self.args()],
                                capture_output=True, text=True, encoding="utf-8", check=False)
        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.stdout, self.invoke(self.args())[1])

    def test_openssl_binary_salt_explicit_sha256_and_varied_lengths(self):
        openssl = find_openssl()
        if not openssl:
            self.skipTest("OpenSSL не найден")
        for salt in (b"salt", SALT, b"\x00\xff\x00"):
            for length in (1, 16, 32, 33, 100):
                reference = subprocess.run(
                    [openssl, "kdf", "-keylen", str(length), "-binary", "-kdfopt", "digest:SHA256",
                     "-kdfopt", "pass:public-test-password", "-kdfopt", f"hexsalt:{salt.hex()}",
                     "-kdfopt", "iter:3", "PBKDF2"], capture_output=True, check=True,
                ).stdout
                code, stdout, _ = self.invoke(["derive", "--password", "public-test-password", "--salt", salt.hex(),
                                              "--iterations", "3", "--length", str(length)])
                self.assertEqual(code, 0)
                self.assertEqual(bytes.fromhex(stdout.split("  ")[0]), reference)


if __name__ == "__main__":
    unittest.main()
