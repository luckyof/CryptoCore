import contextlib
import io
import tempfile
import unittest
from pathlib import Path

from cryptocore.cli import build_parser, main


KEY = "000102030405060708090a0b0c0d0e0f"


class CliTests(unittest.TestCase):
    def test_parser_rejects_conflicting_operations(self) -> None:
        error_output = io.StringIO()
        with contextlib.redirect_stderr(error_output), self.assertRaises(SystemExit) as exit_error:
            build_parser().parse_args(
                [
                    "--algorithm", "aes", "--mode", "ecb", "--encrypt", "--decrypt",
                    "--key", KEY, "--input", "input.bin",
                ]
            )
        self.assertNotEqual(exit_error.exception.code, 0)
        self.assertIn("нельзя использовать вместе", error_output.getvalue())

    def test_parser_rejects_non_hexadecimal_key(self) -> None:
        error_output = io.StringIO()
        invalid_key = "z" * 32
        with contextlib.redirect_stderr(error_output), self.assertRaises(SystemExit) as exit_error:
            build_parser().parse_args(
                [
                    "--algorithm", "aes", "--mode", "ecb", "--encrypt",
                    "--key", invalid_key, "--input", "input.bin",
                ]
            )
        self.assertNotEqual(exit_error.exception.code, 0)
        self.assertIn("только шестнадцатеричные символы", error_output.getvalue())

    def test_parser_rejects_key_with_wrong_length(self) -> None:
        error_output = io.StringIO()
        with contextlib.redirect_stderr(error_output), self.assertRaises(SystemExit) as exit_error:
            build_parser().parse_args(
                [
                    "--algorithm", "aes", "--mode", "ecb", "--encrypt",
                    "--key", "00ff", "--input", "input.bin",
                ]
            )
        self.assertNotEqual(exit_error.exception.code, 0)
        self.assertIn("ровно 32 шестнадцатеричных символа", error_output.getvalue())

    def test_parser_reports_missing_arguments_in_russian(self) -> None:
        error_output = io.StringIO()
        with contextlib.redirect_stderr(error_output), self.assertRaises(SystemExit):
            build_parser().parse_args([])
        message = error_output.getvalue()
        self.assertIn("не указаны обязательные аргументы", message)
        self.assertNotIn("required", message)

    def test_parser_reports_invalid_choice_in_russian(self) -> None:
        error_output = io.StringIO()
        with contextlib.redirect_stderr(error_output), self.assertRaises(SystemExit):
            build_parser().parse_args(
                [
                    "--algorithm", "des", "--mode", "ecb", "--encrypt",
                    "--key", KEY, "--input", "input.bin",
                ]
            )
        message = error_output.getvalue()
        self.assertIn("недопустимое значение", message)
        self.assertNotIn("invalid choice", message)

    def test_parser_reports_unknown_argument_in_russian(self) -> None:
        error_output = io.StringIO()
        with contextlib.redirect_stderr(error_output), self.assertRaises(SystemExit):
            build_parser().parse_args(
                [
                    "--algorithm", "aes", "--mode", "ecb", "--encrypt",
                    "--key", KEY, "--input", "input.bin", "--unknown",
                ]
            )
        message = error_output.getvalue()
        self.assertIn("нераспознанные аргументы", message)
        self.assertNotIn("unrecognized arguments", message)

    def test_file_round_trip(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            source = root / "source.bin"
            encrypted = root / "encrypted.bin"
            decrypted = root / "decrypted.bin"
            original = bytes(range(256)) + b"CryptoCore\x00"
            source.write_bytes(original)

            encrypt_status = main(
                [
                    "--algorithm", "aes", "--mode", "ecb", "--encrypt",
                    "--key", KEY, "--input", str(source), "--output", str(encrypted),
                ]
            )
            decrypt_status = main(
                [
                    "--algorithm", "aes", "--mode", "ecb", "--decrypt",
                    "--key", KEY, "--input", str(encrypted), "--output", str(decrypted),
                ]
            )

            self.assertEqual(encrypt_status, 0)
            self.assertEqual(decrypt_status, 0)
            self.assertEqual(decrypted.read_bytes(), original)

    def test_default_output_name(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            source = Path(temporary_directory) / "plain.txt"
            source.write_bytes(b"hello")
            status = main(
                [
                    "--algorithm", "aes", "--mode", "ecb", "--encrypt",
                    "--key", KEY, "--input", str(source),
                ]
            )
            self.assertEqual(status, 0)
            self.assertTrue(Path(str(source) + ".enc").is_file())

    def test_missing_input_reports_error(self) -> None:
        error_output = io.StringIO()
        with contextlib.redirect_stderr(error_output):
            status = main(
                [
                    "--algorithm", "aes", "--mode", "ecb", "--encrypt",
                    "--key", KEY, "--input", "missing-file.bin",
                ]
            )
        self.assertNotEqual(status, 0)
        self.assertIn("входной файл не найден", error_output.getvalue())


if __name__ == "__main__":
    unittest.main()
