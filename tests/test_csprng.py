"""Тесты выделенного CSPRNG и автоматической генерации ключей."""

import contextlib
import io
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from cryptocore.cli import main
from cryptocore.csprng import generate_random_bytes, is_weak_aes_key
from cryptocore.errors import CryptoCoreError


GENERATED_KEY = bytes.fromhex("f3a19c742de805b69147ca30856ef2bd")


class CsprngTests(unittest.TestCase):
    def test_requested_length_and_argument_validation(self):
        for size in (0, 1, 16, 4096):
            with self.subTest(size=size):
                self.assertEqual(len(generate_random_bytes(size)), size)
        for invalid in (-1, 1.5, "16", None, True):
            with self.subTest(invalid=invalid), self.assertRaises((TypeError, ValueError)):
                generate_random_bytes(invalid)

    def test_operating_system_failure_is_clear(self):
        with patch("cryptocore.csprng.os.urandom", side_effect=OSError("failure")):
            with self.assertRaisesRegex(CryptoCoreError, "операционной системы"):
                generate_random_bytes(16)

    def test_one_thousand_keys_are_unique(self):
        keys = {generate_random_bytes(16) for _ in range(1000)}
        self.assertEqual(len(keys), 1000)

    def test_hamming_weight_is_near_half(self):
        data = b"".join(generate_random_bytes(16) for _ in range(1000))
        ratio = sum(byte.bit_count() for byte in data) / (len(data) * 8)
        self.assertGreater(ratio, 0.45)
        self.assertLess(ratio, 0.55)

    def test_weak_key_detection(self):
        weak = (
            b"\x00" * 16,
            b"\xff" * 16,
            bytes(range(16)),
            bytes(range(31, 15, -1)),
        )
        for key in weak:
            with self.subTest(key=key.hex()):
                self.assertTrue(is_weak_aes_key(key))
        self.assertFalse(is_weak_aes_key(GENERATED_KEY))


class GeneratedKeyCliTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.source = self.root / "source.bin"
        self.encrypted = self.root / "encrypted.bin"
        self.decrypted = self.root / "decrypted.bin"
        self.original = bytes(range(256)) + b"CryptoCore sprint 3"
        self.source.write_bytes(self.original)

    def test_generated_key_is_printed_once_and_restores_file(self):
        stdout = io.StringIO()
        with patch("cryptocore.cli.generate_random_bytes", return_value=GENERATED_KEY) as random:
            with contextlib.redirect_stdout(stdout):
                status = main([
                    "--algorithm", "aes", "--mode", "ecb", "--encrypt",
                    "--input", str(self.source), "--output", str(self.encrypted),
                ])
        self.assertEqual(status, 0)
        random.assert_called_once_with(16)
        message = stdout.getvalue()
        self.assertEqual(message.count(GENERATED_KEY.hex()), 1)
        self.assertIn("Сгенерирован случайный ключ", message)
        self.assertNotIn(GENERATED_KEY, self.encrypted.read_bytes())

        status = main([
            "--algorithm", "aes", "--mode", "ecb", "--decrypt",
            "--key", GENERATED_KEY.hex(), "--input", str(self.encrypted),
            "--output", str(self.decrypted),
        ])
        self.assertEqual(status, 0)
        self.assertEqual(self.decrypted.read_bytes(), self.original)

    def test_decryption_without_key_is_rejected(self):
        with contextlib.redirect_stderr(io.StringIO()) as errors:
            with self.assertRaises(SystemExit) as exit_error:
                main([
                    "--algorithm", "aes", "--mode", "ecb", "--decrypt",
                    "--input", str(self.source), "--output", str(self.decrypted),
                ])
        self.assertEqual(exit_error.exception.code, 2)
        self.assertIn("необходимо указать --key", errors.getvalue())

    def test_weak_user_key_prints_warning(self):
        with contextlib.redirect_stderr(io.StringIO()) as errors:
            status = main([
                "--algorithm", "aes", "--mode", "ecb", "--encrypt",
                "--key", "00" * 16, "--input", str(self.source),
                "--output", str(self.encrypted),
            ])
        self.assertEqual(status, 0)
        self.assertIn("предупреждение", errors.getvalue())
        self.assertIn("слабым", errors.getvalue())

    def test_key_generation_failure_does_not_create_output(self):
        with patch("cryptocore.cli.generate_random_bytes",
                   side_effect=CryptoCoreError("нет случайных данных")):
            with contextlib.redirect_stderr(io.StringIO()) as errors:
                status = main([
                    "--algorithm", "aes", "--mode", "ecb", "--encrypt",
                    "--input", str(self.source), "--output", str(self.encrypted),
                ])
        self.assertEqual(status, 1)
        self.assertIn("нет случайных данных", errors.getvalue())
        self.assertFalse(self.encrypted.exists())
